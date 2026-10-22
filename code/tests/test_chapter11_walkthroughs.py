"""Book-assembled Chapter 11 listings must retain canonical failure behavior.

The two exercise modules are exact copies of the reviewed book assembly. These
fixtures compare normalized success values and stable failure categories with
the shared implementation. They never contact a service or dispatch a Tool.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CODE_ROOT = Path(__file__).resolve().parents[1]
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

import bounded_body_walkthrough as book_body
import validation_walkthrough as book_request
from chapter11 import bounded_body as canonical_body
from chapter11 import request_validation as canonical_request
from chapter11.errors import ValidationFault


BOOK_SOURCE_SHA256 = {
    "bounded_body_walkthrough.py": "c87e865dd815dfe369e6cfbe6744c360022c2b414798d2221a8f368fa961ac4a",
    "validation_walkthrough.py": "c7f66379a2d69a59f59d673d4bdaeb484982b1bdebecd6098fb9f722f77e6185",
}
CONTEXT = {"userId": "synthetic-user", "tenantId": "synthetic-tenant"}


def request_fixture() -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "search",
            "arguments": {"query": "  approved records  "},
            "_meta": {
                canonical_request.VERSION_KEY: canonical_request.PROTOCOL_VERSION,
                canonical_request.CAPABILITIES_KEY: {},
            },
        },
    }


def _result(operation):
    try:
        return ("accepted", operation())
    except ValidationFault as exc:
        return ("denied", exc.code, exc.http_status)
    except ValueError:
        return ("invalid-policy",)


async def _body_result(reader, chunks, maximum):
    async def stream():
        for chunk in chunks:
            yield chunk

    try:
        return ("accepted", await reader(stream(), maximum))
    except ValidationFault as exc:
        return ("denied", exc.code, exc.http_status)
    except ValueError:
        return ("invalid-policy",)


class BookAssemblyTests(unittest.TestCase):
    def test_exercise_files_match_the_reviewed_book_assembly(self):
        # These public-source fingerprints contain no credential material and
        # remain usable when the private editorial build directory is absent.
        for filename, expected in BOOK_SOURCE_SHA256.items():
            with self.subTest(file=filename):
                actual = hashlib.sha256((CODE_ROOT / filename).read_bytes()).hexdigest()
                self.assertEqual(actual, expected, "book assembly changed; revalidate the printed source")

    def test_imports_work_from_an_unrelated_working_directory(self):
        environment = {"PATH": os.defpath, "PYTHONNOUSERSITE": "1", "PYTHONUTF8": "1"}
        if os.name == "nt" and "SYSTEMROOT" in os.environ:
            environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        with tempfile.TemporaryDirectory(prefix="chapter11-exercise-") as temporary:
            for filename in BOOK_SOURCE_SHA256:
                with self.subTest(file=filename):
                    try:
                        result = subprocess.run(
                            [sys.executable, "-B", os.fspath(CODE_ROOT / filename)],
                            cwd=temporary, env=environment, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            shell=False, timeout=15, check=False,
                        )
                    except subprocess.TimeoutExpired:
                        self.fail(f"{filename} import exceeded its budget; diagnostics withheld")
                    self.assertEqual(result.returncode, 0, f"{filename} import failed; diagnostics withheld")


class BodyWalkthroughParityTests(unittest.TestCase):
    def test_thirteen_body_admission_cases(self):
        cases = (
            ("split-valid", (b"{", b"}"), 2, ("accepted", {})),
            ("empty-chunk", (b"", b"{}"), 2, ("accepted", {})),
            ("bytearray", (bytearray(b"{}"),), 2, ("accepted", {})),
            ("multibyte-view-counts-bytes", (memoryview(b"{}").cast("H"),), 1, ("denied", -32600, 413)),
            ("noncontiguous-view", (memoryview(b"{}{}")[::2],), 4, ("denied", -32700, 400)),
            ("wrong-chunk-type", ("{}",), 2, ("denied", -32700, 400)),
            ("oversize", (b"{}", b" "), 2, ("denied", -32600, 413)),
            ("invalid-utf8", (b"\xff",), 2, ("denied", -32700, 400)),
            ("duplicate-member", (b'{"x":1,"x":2}',), 32, ("denied", -32700, 400)),
            ("non-json-number", (b'{"x":NaN}',), 32, ("denied", -32700, 400)),
            ("excessive-depth", (b"[" * 33 + b"0" + b"]" * 33,), 100, ("denied", -32602, 400)),
            ("boolean-policy", (b"{}",), True, ("invalid-policy",)),
            ("above-ceiling-policy", (b"{}",), canonical_body.MAX_REQUEST_BYTES + 1, ("invalid-policy",)),
        )
        self.assertEqual(len(cases), 13)
        for name, chunks, maximum, expected in cases:
            with self.subTest(case=name):
                actual = asyncio.run(_body_result(book_body.read_bounded_json, chunks, maximum))
                canonical = asyncio.run(_body_result(canonical_body.read_bounded_json, chunks, maximum))
                self.assertEqual(actual, expected)
                self.assertEqual(actual, canonical)


class RequestWalkthroughParityTests(unittest.TestCase):
    def test_twenty_five_normalization_and_rejection_cases(self):
        cases = []

        def add(name, mutate=None, *, context=None, code=None):
            request = request_fixture()
            if mutate is not None:
                mutate(request)
            cases.append((name, request, CONTEXT if context is None else context, code))

        add("search-normalizes-and-defaults")
        add("create-ticket", lambda r: r["params"].update(name="create_ticket", arguments={"title": "  Support case  ", "body": "Synthetic description", "projectId": "123e4567-e89b-42d3-a456-426614174000"}))
        add("resource-read", lambda r: r.update(method="resources/read", params={"uri": "https://resources.internal.example/docs/one", "_meta": r["params"]["_meta"]}))
        add("unknown-method", lambda r: r.update(method="unknown/method"), code=-32601)
        add("missing-version", lambda r: r["params"]["_meta"].pop(canonical_request.VERSION_KEY), code=-32602)
        add("unsupported-revision", lambda r: r["params"]["_meta"].update({canonical_request.VERSION_KEY: "unsupported"}), code=-32022)
        add("wrong-version-type", lambda r: r["params"]["_meta"].update({canonical_request.VERSION_KEY: 1}), code=-32602)
        add("missing-capabilities", lambda r: r["params"]["_meta"].pop(canonical_request.CAPABILITIES_KEY), code=-32602)
        add("wrong-capabilities-type", lambda r: r["params"]["_meta"].update({canonical_request.CAPABILITIES_KEY: []}), code=-32602)
        add("invalid-client-info", lambda r: r["params"]["_meta"].update({"io.modelcontextprotocol/clientInfo": {"name": " ", "version": "1"}}), code=-32602)
        add("boolean-id", lambda r: r.update(id=True), code=-32602)
        add("unsafe-integer-id", lambda r: r.update(id=canonical_request.MAX_SAFE_INTEGER + 1), code=-32602)
        add("blank-context", context={"userId": " ", "tenantId": "tenant"}, code=-32602)
        add("preserve-nonblank-identity", context={"userId": " user ", "tenantId": " tenant "})
        add("unknown-envelope-field", lambda r: r.update(unreviewed=True), code=-32602)
        add("unknown-parameter-field", lambda r: r["params"].update(unreviewed=True), code=-32602)
        add("unknown-tool", lambda r: r["params"].update(name="unreviewed"), code=-32602)
        add("unknown-argument", lambda r: r["params"]["arguments"].update(unreviewed=True), code=-32602)
        add("blank-query", lambda r: r["params"]["arguments"].update(query=" "), code=-32602)
        add("boolean-limit", lambda r: r["params"]["arguments"].update(limit=True), code=-32602)
        add("excess-limit", lambda r: r["params"]["arguments"].update(limit=51), code=-32602)
        add("invalid-project-uuid", lambda r: r["params"].update(name="create_ticket", arguments={"title": "Case", "body": "Description", "projectId": "not-a-uuid"}), code=-32602)
        for name, uri in (
            ("foreign-resource-origin", "https://attacker.example/docs"),
            ("resource-userinfo", "https://user:synthetic@resources.internal.example/docs"),
            ("resource-fragment", "https://resources.internal.example/docs#fragment"),
        ):
            add(name, lambda r, value=uri: r.update(method="resources/read", params={"uri": value, "_meta": r["params"]["_meta"]}), code=-32602)
        self.assertEqual(len(cases), 25)
        for name, raw, context, expected_code in cases:
            with self.subTest(case=name):
                original = copy.deepcopy(raw)
                actual = _result(lambda: book_request.validate_request(copy.deepcopy(raw), copy.deepcopy(context)))
                canonical = _result(lambda: canonical_request.validate_request(copy.deepcopy(raw), copy.deepcopy(context)))
                self.assertEqual(actual, canonical)
                if expected_code is None:
                    self.assertEqual(actual[0], "accepted")
                    self.assertEqual(actual[1]["context"], context)
                    if name == "search-normalizes-and-defaults":
                        self.assertEqual(actual[1]["params"]["arguments"], {"query": "approved records", "limit": 10})
                else:
                    self.assertEqual(actual[:2], ("denied", expected_code))
                self.assertEqual(raw, original)


if __name__ == "__main__":
    unittest.main()
