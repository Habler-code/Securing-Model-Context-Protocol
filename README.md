# Securing Model Context Protocol

Python companion examples for the book published by Packt.

The examples follow the current chapter listings, assemble split snippets into
complete modules, and add offline demonstrations, tests, and chapter-specific
setup notes. Chapter 1 is conceptual; Chapters 2–20 have runnable Python demos.
Each guide explains the assumptions, companion adaptations, and production
integrations that the example does not implement.

## Get started

Use Python 3.12 or later. From the repository root:

```sh
cd code
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip check
python -m unittest discover -s tests -v
```

On Windows, use `.venv\Scripts\Activate.ps1` to activate the environment in
PowerShell. Chapter 8's process example is POSIX-specific and requires macOS or
Linux with a protected, root-owned `/usr/bin/git`.

Try an individual example:

```sh
python chapter04/token_authorization.py
python chapter11/demo.py
python chapter20/hitl_controls.py
```

The offline suite needs no identity-provider account, cloud resource, model,
database, or production credential. It does not start a real MCP service or
execute administrative Tools. All executable companion sources are Python;
supporting files include JSON configuration, an illustrative Compose baseline,
and a PostgreSQL fixture. Chapter 11's printed Python listings are assembled in
`code/bounded_body_walkthrough.py` and `code/validation_walkthrough.py`, using
the shared validation helpers described in its guide.

## Navigate the examples

- [Chapter index, setup and boundaries](code/README.md)
- [Validation scope and integration requirements](code/VALIDATION.md)
- [Automated tests](code/tests/)

These are educational security patterns, not drop-in production services.
Passing the offline tests is not a guarantee of complete MCP conformance,
vulnerability freedom, or regulatory compliance. Review the chapter-specific
trust assumptions before adapting a module.

## License

See [LICENSE](LICENSE).
