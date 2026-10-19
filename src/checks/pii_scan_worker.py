"""Standalone PII scan worker — executed inside the pii-scan container.

Scans source text files with Microsoft Presidio (presidio-analyzer) and
emits a machine-readable result on stdout:
    TRUENORTH_RESULT: {"check":"pii-scan", ...}

Severity model (TrueNorth FR-58/59/71):
    strict  entities (SSN, credit card, passport, bank account)  -> FAIL the check
    soft    entities (email, phone, IP, person names in prose)   -> report only
This keeps the required-class gate honest: hard PII (government/financial
identifiers) always blocks; contact-info noise in docs/READMEs is surfaced
without breaking every pipeline.
"""

import json
import os
import sys

SOURCE_ROOT = os.environ.get("PII_SOURCE_ROOT", "/src")

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "__pycache__", "dist", "build", "site"}
SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".xz",
    ".7z", ".so", ".o", ".a", ".bin", ".woff", ".woff2", ".ttf", ".mp3", ".mp4",
    ".exe", ".dll", ".class", ".jar", ".whl", ".pyc", ".min.js", ".min.css", ".svg",
}
MAX_FILE_BYTES = 512 * 1024          # skip anything bigger (models, fixtures)
MIN_SCORE_SOFT = 0.55                # recognizer confidence floor (soft entities)
# Strict entities: SSN patterns cap at 0.5 without spaCy context boosting
# (quick mode has no NER) — the recognizer's own area/group/serial
# validation is the real filter at that tier.
MIN_SCORE_STRICT = 0.50
STRICT_ENTITIES = {
    "US_SSN", "CREDIT_CARD", "US_PASSPORT", "US_PASSPORT_NUMBER",
    "US_BANK_NUMBER", "US_BANK_ROUTING", "US_ITIN", "IBAN_CODE",
    "ES_NIF", "SG_NRIC_FIN", "AU_MEDICARE", "AU_TFN",
}
SOFT_ENTITIES = {
    "EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS",
}
# NER entities (PERSON/ORGANIZATION/LOCATION) fire constantly on code
# identifiers ("Run", "def test_...") — reported only when STRICT, never soft.

TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini",
    ".sh", ".c", ".h", ".cpp", ".hpp", ".go", ".rs", ".js", ".ts", ".html",
    ".css", ".sql", ".csv", ".xml", ".env", ".conf", ".am", ".ac", ".mk",
    "dockerfile", "makefile", "license", "readme",
}


def is_text(name):
    base = name.lower()
    if base in TEXT_SUFFIXES or os.path.splitext(base)[1] in TEXT_SUFFIXES:
        return True
    for suf in TEXT_SUFFIXES:
        if base.endswith(suf) and len(suf) > 1:
            return True
    return False


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size == 0 or size > MAX_FILE_BYTES:
                continue
            if not is_text(fn):
                # sniff: reject obvious binaries
                try:
                    with open(path, "rb") as fh:
                        if b"\x00" in fh.read(8192):
                            continue
                except OSError:
                    continue
            yield path


class _NoOpNlpArtifacts:
    """Duck-typed stand-in for presidio's NlpArtifacts.

    The concrete class wants a spaCy Doc, which quick mode deliberately
    doesn't install — and the result type moved between presidio versions
    (NlpArtifacts in 2.2.35, NlpEngineResult later), so importing it is a
    portability trap. Consumers only attribute-access: empty `tokens`
    short-circuits LemmaContextAwareEnhancer's lemmatization, and pattern
    recognizers never touch the engine anyway.
    """

    tokens = []
    tokens_indices = []
    lemmas = []
    keywords = []
    entities = []
    scores = []
    nlp_engine_name = "noop"

    def to_json(self):  # noqa: ANN201
        return "{}"


class _NoOpNlpEngine:
    """Minimal NlpEngine stand-in for quick mode (pattern recognizers only).

    Pattern recognizers never call the NLP engine, so an inert engine keeps
    the analyzer happy without loading spaCy. Same trick Presidio's own
    tests use (TestNlpEngine).
    """

    def process_text(self, text, language):  # noqa: ANN001, ANN201
        return _NoOpNlpArtifacts()

    def is_stopword(self, word, language):  # noqa: ANN001, ANN201
        return False

    def is_punct(self, word, language):  # noqa: ANN001, ANN201
        return False

    def get_nlp_engine(self):  # noqa: ANN201
        return self

    def is_loaded(self) -> bool:
        return True

    def get_supported_entities(self, lang=None):  # noqa: ANN001, ANN201
        return []


def main():
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry

    mode = os.environ.get("PII_MODE", "quick")
    registry = RecognizerRegistry()
    if mode == "full":
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        nlp_conf = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        nlp_engine = NlpEngineProvider(nlp_configuration=nlp_conf).create_engine()
        analyzer = AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)
    else:
        analyzer = AnalyzerEngine(nlp_engine=_NoOpNlpEngine(), registry=registry)

    files_scanned = 0
    files_failed = 0
    strict, soft = [], []
    for path in iter_files(SOURCE_ROOT):
        rel = os.path.relpath(path, SOURCE_ROOT)
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        files_scanned += 1
        try:
            results = analyzer.analyze(text=text, language="en", return_decision_process=False)
        except Exception as exc:  # noqa: BLE001 — a bad file must not kill the scan
            files_failed += 1
            print(f"[pii-scan] WARN analyze failed {rel}: {exc}", file=sys.stderr)
            continue
        seen = set()
        for r in results:
            if r.entity_type in ("URL", "DATE_TIME"):
                continue
            strict_hit = r.entity_type in STRICT_ENTITIES
            if not strict_hit and r.entity_type not in SOFT_ENTITIES:
                continue
            if r.score < (MIN_SCORE_STRICT if strict_hit else MIN_SCORE_SOFT):
                continue
            key = (r.entity_type, r.start // 64)
            if key in seen:
                continue
            seen.add(key)
            excerpt = text[max(0, r.start - 20): r.end + 20]
            excerpt = " ".join(excerpt.split())[:80]
            entry = {
                "entity": r.entity_type,
                "file": rel,
                "line": text.count("\n", 0, r.start) + 1,
                "score": round(r.score, 2),
                "excerpt": excerpt,
            }
            (strict if r.entity_type in STRICT_ENTITIES else soft).append(entry)

    # Required-class honesty (FR-58/59/71): a file we could not analyze is a
    # file we cannot claim is clean — an unscannable file FAILS the check
    # instead of silently passing.
    failed = bool(strict) or files_failed > 0
    payload = {
        "check": "pii-scan",
        "tool": f"presidio-analyzer ({mode} mode)",
        "files_scanned": files_scanned,
        "files_failed": files_failed,
        "strict_findings": len(strict),
        "soft_findings": len(soft),
        "status": "fail" if failed else "pass",
        "strict": strict[:20],
        "soft": soft[:20],
    }
    print("TRUENORTH_RESULT: " + json.dumps(payload))
    if files_failed and not strict:
        print(f"[pii-scan] FAIL: {files_failed} file(s) could not be analyzed")
    elif failed:
        print(f"[pii-scan] FAIL: {len(strict)} strict PII finding(s)")
        for e in strict[:10]:
            print(f"  {e['file']}:{e['line']} {e['entity']} score={e['score']} :: {e['excerpt']}")
        sys.exit(2)
    print(f"[pii-scan] pass: {files_scanned} files, 0 strict, {len(soft)} soft finding(s)")
    for e in soft[:10]:
        print(f"  {e['file']}:{e['line']} {e['entity']} score={e['score']} :: {e['excerpt']}")


if __name__ == "__main__":
    main()
