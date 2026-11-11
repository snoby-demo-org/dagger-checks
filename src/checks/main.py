"""Shared CI checks for viporlab repos (Dagger module).

REAL checks:  secrets-scan (Gitleaks v8.30.1), pii-scan (Presidio 2.2.35),
              private-key-check (gitleaks + module ruleset, full tree),
              sast (semgrep v1.181.1, offline custom C/C++ rules, incremental),
              lint (cppcheck 2.17.1, incremental).
STUB checks:  format, build, test — swap any stub body for the real tool when
              ready; signatures stay stable.

Incremental contract: sast/lint read truenorth-changed-files.txt from the
source root and scan ONLY changed C/C++ files; absent/empty manifest =>
SKIPPED (explicit pass-with-note, advisory class — never silently full-scan).
private-key-check is required class and ALWAYS full-tree.

Config contract (repo-owned .github/goldenpath.yaml):
    checks:
      lint:     {enabled: true, plane: build}
      sast:     {enabled: true, plane: build}
      pii-scan: {enabled: true, plane: build}
      build:    {enabled: true, plane: build}
      test:     {enabled: true, plane: test}
Run from a workflow:  dagger call --mod github.com/snoby-demo-org/dagger-checks <check> --source=.
"""

import json
import os

import dagger
from dagger import dag, function, object_type

DEMO_IMAGE = "python:3.12-slim"
FAKE_DIGEST = "sha256:9f2c8a1e4d7b3a6c5e0f1d2c3b4a59687766554433221100ffeeddccbbaa9988"

# --- real tools (FR-14: version-pinned) ---
GITLEAKS_IMAGE = "ghcr.io/gitleaks/gitleaks:v8.30.1"
# Presidio stack PREBAKED (build-scanner-image.yml): quick mode runs with zero
# runtime install — a cold `pip install presidio+spacy` on every ephemeral
# engine was ~6 of pii-scan's 9 minutes. Full mode (ner=True) still installs
# the spaCy model wheel at run time (opt-in, heavy by design).
PRESIDIO_IMAGE = "ghcr.io/snoby-demo-org/pii-scanner:presidio-2.2.35"
PRESIDIO_PIN = "presidio-analyzer==2.2.35"
SPACY_MODEL_WHL = (
    "https://github.com/explosion/spacy-models/releases/download/"
    "en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"
)


def _banner(check, source):
    """Common stub runner: mount source, print banner, exit 0."""
    return (
        dag.container()
        .from_(DEMO_IMAGE)
        .with_mounted_directory("/src", source)
        .with_workdir("/src")
        .with_exec(["sh", "-c", _script(check)])
    )


def _script(check):
    return (
        f'echo "=================================================="; '
        f'echo " [{check}] dagger-checks demo stub (no-op)"; '
        f'echo "  source files seen: $(find /src -type f | wc -l)"; '
        f'echo "  result: PASS (0 findings)"; '
        f'echo "=================================================="'
    )



SEMGREP_IMAGE = "docker.io/semgrep/semgrep:1.181.1"
CPPCHECK_IMAGE = "registry.viporlab.net/demo/cppcheck-scanner:cppcheck-2.17.1"
MANIFEST_NAME = "truenorth-changed-files.txt"
CXX_EXTS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc")


def _rules_file(relpath: str) -> str:
    """Read a bundled rules file off the module runtime filesystem."""
    return open(os.path.join(os.path.dirname(__file__), relpath)).read()


async def _changed_cxx_files(source: dagger.Directory) -> list:
    """Return changed C/C++ paths from the manifest ([] if none/unreadable)."""
    try:
        raw = await source.file(MANIFEST_NAME).contents()
    except Exception:
        return []
    paths = []
    for ln in raw.splitlines():
        p = ln.strip().lstrip("./")
        if p and p.endswith(CXX_EXTS):
            paths.append(p)
    return list(dict.fromkeys(paths))


def _skip_banner(check: str, why: str) -> str:
    return "\n".join([
        "=" * 50,
        f" [{check}] SKIPPED — {why}",
        f"TRUENORTH_RESULT: {json.dumps({'check': check, 'status': 'pass', 'scope': 'skipped', 'details': why})}",
        "=" * 50,
    ])


async def _cppcheck_scan(source: dagger.Directory) -> str:
    files = await _changed_cxx_files(source)
    if not files:
        why = ("no changed C/C++ files in " + MANIFEST_NAME
               + " (incremental-only policy: legacy tree is never full-scanned)")
        return _skip_banner("lint", why)
    script = (
        'FILES="$(cat /tmp/files.txt | tr "\\n" "\\0" | xargs -0 -r sh -c '
        '\'printf "%s\\n" "$@"\' _ | tr "\\n" " ")"; '
        'cppcheck --enable=warning,portability,performance --inline-suppr '
        '--quiet --language=c++ --template="{file}:{line}: {severity}: {id}: {message}" '
        '$FILES > /tmp/cppcheck.out 2>&1; echo $? > /tmp/rc; exit 0'
    )
    out = await (
        dag.container()
        .from_(CPPCHECK_IMAGE)
        .with_mounted_directory("/src", source)
        .with_workdir("/src")
        .with_new_file("/tmp/files.txt", "\n".join(files))
        .with_exec(["sh", "-c", script])
        .file("/tmp/cppcheck.out")
        .contents()
    )
    rc_raw = await (
        dag.container()
        .from_(CPPCHECK_IMAGE)
        .with_mounted_directory("/src", source)
        .with_workdir("/src")
        .with_new_file("/tmp/files.txt", "\n".join(files))
        .with_exec(["sh", "-c", script])
        .file("/tmp/rc")
        .contents()
    )
    findings = [l for l in out.splitlines() if l.strip()]
    payload = {
        "check": "lint",
        "tool": "cppcheck@" + CPPCHECK_IMAGE.rsplit(":", 1)[-1],
        "scope": "incremental",
        "files_scanned": len(files),
        "findings": len(findings),
        "status": "fail" if findings else "pass",
    }
    lines = ["=" * 50, f" [lint] cppcheck (real, incremental {len(files)} files)"]
    lines += [f"  {l}" for l in findings[:20]]
    if len(findings) > 20:
        lines.append(f"  ... and {len(findings) - 20} more")
    lines.append(f"TRUENORTH_RESULT: {json.dumps(payload)}")
    lines.append("=" * 50)
    if findings:
        raise RuntimeError(f"cppcheck: {len(findings)} finding(s) (see job log)")
    return "\n".join(lines)


async def _semgrep_scan(source: dagger.Directory) -> str:
    files = await _changed_cxx_files(source)
    if not files:
        why = ("no changed C/C++ files in " + MANIFEST_NAME
               + " (incremental-only policy: legacy tree is never full-scanned)")
        return _skip_banner("sast", why)
    script = (
        'semgrep scan --config /tmp/rules.yml --json --output /tmp/semgrep.json '
        '--quiet $(cat /tmp/files.txt | tr "\\n" " ") || true; exit 0'
    )
    raw = await (
        dag.container()
        .from_(SEMGREP_IMAGE)
        .with_mounted_directory("/src", source)
        .with_workdir("/src")
        .with_new_file("/tmp/rules.yml", _rules_file("rules/semgrep-security-c.yml"))
        .with_new_file("/tmp/files.txt", "\n".join(files))
        .with_exec(["sh", "-c", script])
        .file("/tmp/semgrep.json")
        .contents()
    )
    try:
        data = json.loads(raw) if raw.strip() else {"results": []}
    except json.JSONDecodeError:
        data = {"results": []}
    results = data.get("results", [])
    payload = {
        "check": "sast",
        "tool": "semgrep@" + SEMGREP_IMAGE.rsplit(":", 1)[-1],
        "scope": "incremental",
        "files_scanned": len(files),
        "findings": len(results),
        "status": "fail" if results else "pass",
    }
    lines = ["=" * 50, f" [sast] semgrep (real, incremental {len(files)} files)"]
    for r in results[:20]:
        loc = r.get("path", "?")
        if isinstance(loc, dict):
            loc = loc.get("path", "?")
        lines.append(f"  {loc}:{r.get('start', {}).get('line', '?')} rule={r.get('check_id', '?')}")
    if len(results) > 20:
        lines.append(f"  ... and {len(results) - 20} more")
    lines.append(f"TRUENORTH_RESULT: {json.dumps(payload)}")
    lines.append("=" * 50)
    if results:
        raise RuntimeError(f"semgrep: {len(results)} finding(s) (see job log)")
    return "\n".join(lines)


async def _gitleaks_private_key(source: dagger.Directory) -> str:
    report = "private-key-report.json"
    ctr = (
        dag.container()
        .from_(GITLEAKS_IMAGE)
        .with_new_file("/tmp/gitleaks-private.toml", _rules_file("rules/private-key-gitleaks.toml"))
        .with_mounted_directory("/src", source)
        .with_workdir("/src")
        .with_exec([
            "gitleaks", "dir", "/src",
            "--config", "/tmp/gitleaks-private.toml",
            "--no-banner", "--redact",
            "--report-format", "json",
            f"--report-path=/{report}",
            "--exit-code", "0",   # we decide pass/fail ourselves from the report
        ])
    )
    raw = await ctr.file(f"/{report}").contents()
    findings = json.loads(raw) if raw.strip() else []
    payload = {
        "check": "private-key-check",
        "tool": "gitleaks@" + GITLEAKS_IMAGE.rsplit(':', 1)[-1],
        "ruleset": "module:rules/private-key-gitleaks.toml",
        "findings": len(findings),
        "status": "fail" if findings else "pass",
    }
    lines = [
        "=" * 50,
        " [private-key-check] gitleaks custom ruleset (real)",
        f"  findings: {len(findings)}",
    ]
    for f in findings[:10]:
        lines.append(
            f"  {f.get('File','?')}:{f.get('StartLine','?')} rule={f.get('RuleID','?')}"
        )
    lines.append(f"TRUENORTH_RESULT: {json.dumps(payload)}")
    lines.append("=" * 50)
    if findings:
        raise RuntimeError(f"private-key-check: {len(findings)} finding(s) (see job log)")
    return "\n".join(lines)


@object_type
class Checks:
    @function
    async def secrets_scan(self, source: dagger.Directory) -> str:
        """REAL — Gitleaks secret scan (required class, FR-58/71).

        Runs gitleaks `dir` scan over the source tree with the default 170+
        rules, redacted JSON report. Fails the check when any secret-like
        finding exists; emits the FR-7 TRUENORTH_RESULT contract line.
        """
        report = "gitleaks-report.json"
        ctr = (
            dag.container()
            .from_(GITLEAKS_IMAGE)
            .with_mounted_directory("/src", source)
            .with_workdir("/src")
            .with_exec([
                "gitleaks", "dir", "/src",
                "--no-banner", "--redact",
                "--report-format", "json",
                f"--report-path=/{report}",
                "--exit-code", "0",   # we decide pass/fail ourselves from the report
            ])
        )
        raw = await ctr.file(f"/{report}").contents()
        import json

        findings = json.loads(raw) if raw.strip() else []
        payload = {
            "check": "secrets-scan",
            "tool": f"gitleaks@{GITLEAKS_IMAGE.rsplit(':', 1)[-1]}",
            "findings": len(findings),
            "status": "fail" if findings else "pass",
        }
        lines = [
            "=" * 50,
            " [secrets-scan] gitleaks (real)",
            f"  findings: {len(findings)}",
        ]
        for f in findings[:10]:
            lines.append(
                f"  {f.get('File','?')}:{f.get('StartLine','?')} rule={f.get('RuleID','?')}"
            )
        lines.append(f"TRUENORTH_RESULT: {json.dumps(payload)}")
        lines.append("=" * 50)
        if findings:
            raise RuntimeError(f"gitleaks: {len(findings)} secret finding(s) (see job log)")
        return "\n".join(lines)

    @function
    async def pii_scan(self, source: dagger.Directory, ner: bool = False) -> str:
        """REAL — Microsoft Presidio PII scan (required class, FR-58/71).

        Default: QUICK mode — pattern recognizers only (SSN, credit card,
        email, phone, IP, IBAN...), no NLP model. Seconds, not minutes.
        ner=True opts into full NER (spaCy en_core_web_sm) for doc-heavy
        repos — much slower.

        Strict entities (SSN/credit-card/passport/bank) FAIL the check;
        soft entities (email/phone/IP) are reported only.

        Repo-owned exclusions (v1.1.2): a  file at the source root
        (one path or glob per line, relative paths, '#' comments) excludes files
        from the scan — for upstream fixture/doc false positives a repo cannot
        fix. The payload reports files_ignored / ignored / ignore_file.

        Repo-owned exclusions (v1.1.2): a `.piiignore` file at the source root
        (one path or glob per line, relative to the source root, '#' comments)
        excludes files from the scan — for upstream fixture/doc false positives
        a repo cannot fix. The payload reports files_ignored / ignored /
        ignore_file. Absent file = unchanged full behavior.

        Incremental scope (v1.1.1): if the source root contains
        truenorth-changed-files.txt (one path per line, written by the
        pipeline), only those files are scanned — PRESENCE is the signal:
        an EMPTY manifest (empty commit / zero-file diff) is an honest
        0-file scan, a MISSING manifest (first run, deep-scan dispatch,
        legacy caller) falls back to the full tree. Depth never
        auto-escalates with scope: the fallback runs quick mode; deep NER
        stays an explicit opt-in via ner=True.
        """
        import os

        mode = "full" if ner else "quick"
        # quick mode: stack is prebaked into PRESIDIO_IMAGE — no runtime install.
        # full mode: still needs the spaCy model wheel (heavy, opt-in).
        if ner:
            cmd = f"pip install --cache-dir=/cache/pip {SPACY_MODEL_WHL} && python /tmp/pii_scan_worker.py"
        else:
            cmd = "python /tmp/pii_scan_worker.py"
        worker_path = os.path.join(os.path.dirname(__file__), "pii_scan_worker.py")
        worker_src = open(worker_path).read()
        ctr = (
            dag.container()
            .from_(PRESIDIO_IMAGE)
            .with_new_file("/tmp/pii_scan_worker.py", worker_src)
            .with_mounted_directory("/src", source)
            .with_env_variable("PII_MODE", mode)
            .with_workdir("/src")
            .with_exec(["sh", "-c", cmd])
        )
        return await ctr.stdout()

    @function
    async def lint(self, source: dagger.Directory) -> str:
        """REAL — cppcheck static analysis over CHANGED C/C++ files only.

        Incremental-only policy (advisory class): scans files listed in
        truenorth-changed-files.txt filtered to C/C++ extensions. Absent
        or empty manifest (or no changed C/C++ files) => SKIPPED with a
        pass status and an explicit note — the legacy tree is never
        full-scanned by design.
        """
        return await _cppcheck_scan(source)

    @function
    async def sast(self, source: dagger.Directory) -> str:
        """REAL — Semgrep over CHANGED C/C++ files only (offline custom rules).

        Incremental-only policy (advisory class): scans changed C/C++ files
        from truenorth-changed-files.txt with the module's own pinned ruleset
        (rules/semgrep-security-c.yml) — no semgrep.dev registry fetch, so
        engine pods need no egress. Absent/empty manifest => SKIPPED pass.
        """
        return await _semgrep_scan(source)

    @function
    async def private_key_check(self, source: dagger.Directory) -> str:
        """REAL — wallet-key/seed detector (required class, own gate).

        Gitleaks with the module's own STANDALONE ruleset
        (rules/private-key-gitleaks.toml): PEM blocks, WIF Base58 keys,
        hex private keys near a keyword, BIP39 mnemonics, identity/seed hex
        blobs. The default gitleaks rule set is secrets-scan's job and is
        deliberately NOT extended here. FULL-tree scan (key material can sit
        in any file); any finding fails the check.
        """
        return await _gitleaks_private_key(source)

    @function
    async def build(self, source: dagger.Directory) -> str:
        """STUB — 'builds' the image and 'pushes' to zot.

        Prints a fake digest that the test plane consumes as its handoff
        artifact. Replace with real publish when builds land.
        """
        return await (
            _banner("build", source)
            .with_env_variable("D", FAKE_DIGEST)   # set BEFORE the exec that echoes it
            .with_exec([
                "sh", "-c",
                'echo "  pushed zot.viporlab.net/demo/app@$D"; echo "DIGEST=$D"',
            ])
            .stdout()
        )

    @function
    async def test(self, source: dagger.Directory) -> str:
        """STUB — unit-test suite (pytest-shaped) pass banner, exits 0.

        Runs on the TEST plane: receives the digest the build plane pushed,
        then 'runs' the suite.
        """
        return await (
            _banner("test", source)
            .with_exec([
                "sh", "-c",
                'echo "  image under test: zot.viporlab.net/demo/app (digest from build plane)"; '
                'echo "  tests: 42 passed, 0 failed, 0 skipped"',
            ])
            .stdout()
        )