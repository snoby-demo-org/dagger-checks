"""Shared CI checks for viporlab repos (Dagger module) — DEMO EDITION.

Every check is a NO-OP that prints a realistic banner and passes. The point
of this edition is to demo the ASSEMBLY: config-driven routing, two-plane
build/test split, zot digest handoff, Backstage/GHA visibility. Swap any stub
body for the real tool when ready — signatures stay stable.

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
    async def lint(self, source: dagger.Directory) -> str:
        """STUB — prints ruff-style pass banner, exits 0."""
        return await _banner("lint", source).stdout()

    @function
    async def sast(self, source: dagger.Directory) -> str:
        """STUB — static analysis (semgrep/bandit-shaped) pass banner, exits 0."""
        return await _banner("sast", source).stdout()

    @function
    async def pii_scan(self, source: dagger.Directory) -> str:
        """STUB — secrets/PII scan (gitleaks-shaped) pass banner, exits 0."""
        return await _banner("pii-scan", source).stdout()

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
            .with_exec([
                "sh", "-c",
                'echo "  pushed zot.viporlab.net/demo/app@$D"; echo "DIGEST=$D"',
            ])
            .with_env_variable("D", FAKE_DIGEST)
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
