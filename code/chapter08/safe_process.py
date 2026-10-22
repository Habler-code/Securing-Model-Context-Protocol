"""Chapter 8: narrow no-shell process operations for a POSIX host.

No vulnerable software is installed and no CVE exploit is reproduced.
The executable and repository paths are deployment policy, not tool arguments.
"""

from __future__ import annotations

import os
import selectors
import signal
import stat
import subprocess
import time
from pathlib import Path
from typing import Sequence

GIT = Path("/usr/bin/git")
ALLOWED_COMMANDS = {"git": (GIT, ("--version",))}
MAX_OUTPUT_BYTES = 64 * 1024


def _verify_binary(path: Path) -> Path:
    if os.name != "posix" or not path.is_absolute():
        raise PermissionError("this example requires a trusted absolute POSIX executable")
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
        raise PermissionError("executable must be a root-owned regular file")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or not os.access(resolved, os.X_OK):
        raise PermissionError("executable permissions are unsafe")
    # Each ancestor must also be protected; a trusted file in a writable
    # directory can otherwise be replaced between checks and execution.
    for directory in resolved.parents:
        metadata = directory.stat()
        if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError("executable directory is not trusted")
    return resolved


def _repo_relative_paths(repo: Path, values: Sequence[str]) -> list[str]:
    repo = repo.resolve(strict=True)
    if not values or len(values) > 20:
        raise PermissionError("one to twenty explicit path operands are required")
    safe: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise PermissionError("invalid path operand")
        if value.startswith("-") or "\x00" in value or Path(value).is_absolute():
            raise PermissionError("invalid path operand")
        candidate = (repo / value).resolve(strict=False)
        if not candidate.is_relative_to(repo):
            raise PermissionError("path escapes repository")
        relative = candidate.relative_to(repo)
        if not relative.parts or relative.parts[0] == ".git":
            raise PermissionError("repository metadata is not an approved operand")
        safe.append(relative.as_posix())
    return safe


def _run_bounded(argv: Sequence[str], *, cwd: Path, timeout: float = 5) -> str:
    """Bound wall time and combined output; do not inherit the caller's secrets."""
    if timeout <= 0 or timeout > 30:
        raise ValueError("invalid timeout policy")
    env = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
    }
    with subprocess.Popen(
        list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, cwd=cwd, env=env, shell=False,
        start_new_session=True,
    ) as process:
        assert process.stdout is not None
        output = bytearray()
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("process exceeded execution budget")
                    if not selector.select(remaining):
                        raise TimeoutError("process exceeded execution budget")
                    chunk = os.read(process.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_OUTPUT_BYTES:
                        raise ValueError("process output exceeds policy")
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if process.returncode:
                # Raw diagnostics may contain paths or secrets. Do not return them.
                raise RuntimeError("approved process failed")
            return bytes(output).decode("utf-8", errors="replace").strip()
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise


def run_safe(cmd: str, args: Sequence[str]) -> str:
    """Accept an exact command/argument tuple, not just allowlisted flags.

    This fixes the original skeleton's gap: `node script.js` or `git arbitrary`
    must not pass simply because a positional argument lacks a leading dash.
    """
    policy = ALLOWED_COMMANDS.get(cmd)
    if policy is None or tuple(args) != policy[1]:
        raise PermissionError("operation not allowlisted")
    binary = _verify_binary(policy[0])
    return _run_bounded([os.fspath(binary), *args], cwd=Path("/"))


def run_git_diff(repo: Path, paths: Sequence[str]) -> str:
    """Read a diff in a repository selected by trusted deployment configuration.

    Repository contents may change, but ownership and mounts must prevent an
    attacker replacing the repository or executable while the operation runs.
    """
    repo = repo.resolve(strict=True)
    if not repo.is_dir() or not (repo / ".git").exists():
        raise PermissionError("configured directory is not a repository")
    git = _verify_binary(GIT)
    operands = _repo_relative_paths(repo, paths)
    return _run_bounded(
        [os.fspath(git), "--no-pager", "--literal-pathspecs", "-c", "core.fsmonitor=false",
         "-c", "core.hooksPath=/dev/null", "-C", os.fspath(repo), "diff",
         "--no-ext-diff", "--no-textconv", "--ignore-submodules=all", "--", *operands],
        cwd=repo,
    )


def demo() -> None:
    print(run_safe("git", ["--version"]))
    for command, arguments in [("git", ["status"]), ("node", ["untrusted.js"])]:
        try:
            run_safe(command, arguments)
        except PermissionError:
            print(f"Blocked unapproved {command} operation.")


if __name__ == "__main__":
    demo()
