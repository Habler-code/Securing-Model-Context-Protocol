# Chapter 8 — Analyze execution-boundary failures

`safe_process.py` provides the chapter's no-shell process pattern as a working POSIX implementation. It does not install vulnerable software or reproduce a CVE exploit.

The current Chapter 8 export was reviewed on 22 October 2026. Its revised `GIT`, `_verify_binary`, `_repo_relative_paths`, and `run_git_diff` API is retained. Extra companion safeguards bound output and process time, use literal pathspecs, inspect executable ancestors, and disable known Git execution integrations. The old exact version probe is an auxiliary demo, not the revised chapter's main dynamic-path example.

From the repository's `code` directory, on macOS or Linux with a root-owned `/usr/bin/git`:

```sh
python3 chapter08/safe_process.py
python3 -m unittest discover -s tests -p test_middle_python.py -v
```

The demo runs only `git --version` and shows rejected positional arguments and an unapproved Node script. The Python tests use fixed local child fixtures to verify output and time budgets; they use no external service.

## Relation to the chapter

| Manuscript section | Companion implementation |
| --- | --- |
| Command injection in remote wrappers | `run_safe` accepts an exact operation, not just flags beginning with `-` |
| Implementation: safe process execution pattern | Absolute executable, trusted ownership, no shell, minimal environment, no stdin, bounded output and wall time |
| File tampering / path boundary discussion | `_repo_relative_paths` rejects traversal, absolute paths, options, repository metadata, and symlink escapes |
| Revised safe Git diff pattern | `run_git_diff` adds `--`, uses literal pathspecs, and disables external diff/textconv, pagers, fsmonitor, hooks and submodule traversal |

`run_git_diff(repo, paths)` is a library helper for a repository selected by **trusted launch configuration**. Pass explicit repository-relative file operands, for example `run_git_diff(approved_repo, ["README.md"])`. The helper is not a generic command tool or a grant to select any repository on the host. It may read confidential changes: apply caller authorization before invoking it and classify the result before returning it to a model.

## Additions to the teaching skeleton

Checking flags alone would still permit positional arguments, including scripts. The runnable probe therefore accepts only Git's exact `--version` operation. The separate `run_git_diff` helper follows the chapter's repository-relative path example. Its configuration disables pagers, external diff, textconv, hooks and fsmonitor subprocesses. Startup configuration and global/system Git configuration are excluded from the child environment.

The executable and every resolved ancestor must be root-owned and not group/world writable. The deployment must protect the repository and executable from concurrent replacement. These path checks do not replace an OS sandbox or remove every filesystem race. The example targets POSIX because it uses process groups and selectors; it is not a Windows implementation.

Output is limited to 64 KiB and execution to five seconds. Failures return a generic error rather than raw diagnostics. A deployment must also bound concurrency, total process resources, and the repository size. No shell metacharacter is interpreted by these functions.

Tests cover the exact operation allowlist, argument rejection, path traversal, symlink escape, Git execution options, minimal inherited environment, excessive output, and timeouts. They do not establish immunity to sandbox escape or validate the historical CVE narratives.

Security review: no secrets or certificates are included; the only executable selected by the public API is a fixed, checked Git path. No cryptographic API is needed here.

Primary API reference: [Python subprocess documentation](https://docs.python.org/3/library/subprocess.html). Git behavior: [git-diff](https://git-scm.com/docs/git-diff) and [git-config](https://git-scm.com/docs/git-config).
