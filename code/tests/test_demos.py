"""Run the 19 real offline chapter entry points in fresh Python processes.

Chapter 1 is conceptual and has no invented executable. Chapter 8 is skipped
on non-POSIX systems or when /usr/bin/git and its resolved ancestors do not meet
the example's root-owned, non-writable trust policy. This suite does not claim
that Chapter 8 supports Windows. All other entry points use the current test
interpreter, including its installed dependencies.

Each child starts in an unrelated temporary directory with a minimal environment,
no shell, no stdin, and a fixed execution deadline. Output is captured for smoke
checks, but never included in assertion failures or timeout diagnostics.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


CODE_ROOT = Path(__file__).resolve().parents[1]
DEMO_TIMEOUT_SECONDS = 20
MAX_DEMO_OUTPUT_BYTES = 65_536
DEMO_ENTRYPOINTS = (
    "chapter02/policy_gate.py",
    "chapter03/oauth_pkce.py",
    "chapter04/token_authorization.py",
    "chapter05/principal_mapping.py",
    "chapter06/untrusted_content.py",
    "chapter07/tool_poisoning.py",
    "chapter08/safe_process.py",
    "chapter09/local_config.py",
    "chapter10/egress_firewall.py",
    "chapter11/demo.py",
    "chapter12/tool_index.py",
    "chapter13/secret_cache.py",
    "chapter14/tenant_isolation.py",
    "chapter15/permission_models.py",
    "chapter16/security_design_patterns.py",
    "chapter17/supply_chain_security.py",
    "chapter18/monitoring_observability.py",
    "chapter19/governance_compliance.py",
    "chapter20/hitl_controls.py",
)


def chapter08_skip_reason() -> str | None:
    """Check deployment eligibility only; the chapter tests its own controls."""
    if os.name != "posix":
        return "Chapter 8 requires POSIX; this suite makes no Windows claim"
    try:
        binary = Path("/usr/bin/git").resolve(strict=True)
        metadata = binary.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
            return "Chapter 8 requires a root-owned regular /usr/bin/git"
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or not os.access(binary, os.X_OK):
            return "Chapter 8 requires protected executable permissions"
        for directory in binary.parents:
            metadata = directory.stat()
            if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return "Chapter 8 requires protected root-owned executable ancestors"
    except OSError:
        return "Chapter 8 requires an available trusted /usr/bin/git"
    return None


class ChapterDemoSmokeTests(unittest.TestCase):
    def run_entrypoint(self, relative_path: str) -> None:
        if relative_path.startswith("chapter08/"):
            reason = chapter08_skip_reason()
            if reason is not None:
                self.skipTest(reason)
        entrypoint = CODE_ROOT / relative_path
        self.assertTrue(entrypoint.is_file(), f"missing declared entry point: {relative_path}")
        # Do not inherit API credentials, proxy settings, PYTHONPATH, or user
        # startup configuration from the CI/developer environment.
        environment = {
            "PATH": os.pathsep.join((os.fspath(Path(sys.executable).parent), os.defpath)),
            "LANG": "C.UTF-8",
            "PYTHONUTF8": "1",
            "PYTHONNOUSERSITE": "1",
        }
        # Windows needs this OS setting to locate core system components; no
        # application secrets or authentication variables are inherited.
        if os.name == "nt" and "SYSTEMROOT" in os.environ:
            environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        with tempfile.TemporaryDirectory(prefix="mcp-demo-smoke-") as temporary:
            try:
                result = subprocess.run(
                    [sys.executable, "-B", os.fspath(entrypoint)],
                    cwd=temporary,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    timeout=DEMO_TIMEOUT_SECONDS,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                self.fail(
                    f"{relative_path} exceeded {DEMO_TIMEOUT_SECONDS}s; captured output withheld"
                )
            except OSError as exc:
                self.fail(f"{relative_path} could not start (errno={exc.errno}); diagnostics withheld")
        self.assertEqual(
            result.returncode, 0,
            f"{relative_path} exited with status {result.returncode}; captured output withheld",
        )
        output_size = len(result.stdout) + len(result.stderr)
        self.assertGreater(output_size, 0, f"{relative_path} produced no demonstration output")
        self.assertLessEqual(
            output_size, MAX_DEMO_OUTPUT_BYTES,
            f"{relative_path} exceeded the demonstration output budget; captured output withheld",
        )


def _smoke_test(relative_path: str):
    def test(self: ChapterDemoSmokeTests) -> None:
        self.run_entrypoint(relative_path)

    return test


for _entrypoint in DEMO_ENTRYPOINTS:
    _chapter = _entrypoint.split("/", 1)[0]
    setattr(ChapterDemoSmokeTests, f"test_{_chapter}_entrypoint", _smoke_test(_entrypoint))


if __name__ == "__main__":
    unittest.main()
