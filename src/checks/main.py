"""Shared CI checks for viporlab repos (Dagger module).

REAL checks:  secrets-scan (Gitleaks v8.30.1), pii-scan (Microsoft Presidio 2.2.35).
STUB checks:  lint, sast, format, private-key-check, build, test — swap any stub
body for the real tool when ready; signatures stay stable.

Config contract (repo-owned .github/goldenpath.yaml):
    checks:
      lint:     {enabled: true, plane: build}
      sast:     {enabled: true, plane: build}
      pii-scan: {enabled: true, plane: build}
      build:    {enabled: true, plane: build}
      test:     {enabled: true, plane: test}
Run from a workflow:  dagger call --mod github.com/snoby-demo-org/dagger-checks <check> --source=.
"""

import dagger
from dagger import dag, function, object_type

DEMO_IMAGE = "python:3.12-slim"
FAKE_DIGEST = "sha256:9f2c8a1e4d7b3a6c5e0f1d2c3b4a59687766554433221100ffeeddccbbaa9988"

# --- real tools (FR-14: version-pinned) ---
GITLEAKS_IMAGE = "ghcr.io/gitleaks/gitleaks:v8.30.1"
PRESIDIO_IMAGE = "python:3.12-slim"
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
        """
        import os

        mode = "full" if ner else "quick"
        pkgs = PRESIDIO_PIN
        if ner:
            pkgs += f" {SPACY_MODEL_WHL}"
        install = (
            f"pip install --cache-dir=/cache/pip {pkgs} "
            "&& python /tmp/pii_scan_worker.py"
        )
        worker_path = os.path.join(os.path.dirname(__file__), "pii_scan_worker.py")
        worker_src = open(worker_path).read()
        ctr = (
            dag.container()
            .from_(PRESIDIO_IMAGE)
            .with_mounted_cache("/cache/pip", dag.cache_volume("presidio-pip"))
            .with_new_file("/tmp/pii_scan_worker.py", worker_src)
            .with_mounted_directory("/src", source)
            .with_env_variable("PII_MODE", mode)
            .with_workdir("/src")
            .with_exec(["sh", "-c", install])
        )
        return await ctr.stdout()

    @function
    async def lint(self, source: dagger.Directory) -> str:
        """STUB — prints ruff-style pass banner, exits 0."""
        return await _banner("lint", source).stdout()

    @function
    async def sast(self, source: dagger.Directory) -> str:
        """STUB — static analysis (semgrep/bandit-shaped) pass banner, exits 0."""
        return await _banner("sast", source).stdout()

    @function
    async def format(self, source: dagger.Directory) -> str:
        """STUB — formatter diff gate pass banner, exits 0."""
        return await _banner("format", source).stdout()

    @function
    async def private_key_check(self, source: dagger.Directory) -> str:
        """STUB — wallet-key/seed detector pass banner, exits 0."""
        return await _banner("private-key-check", source).stdout()

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
