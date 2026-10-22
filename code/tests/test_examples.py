from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import unittest


CODE_ROOT = Path(__file__).resolve().parents[1]


def load_example(name: str, relative_path: str):
    path = CODE_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load example: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ch12 = load_example("chapter12_tool_index", "chapter12/tool_index.py")
ch13 = load_example("chapter13_secret_cache", "chapter13/secret_cache.py")
ch14 = load_example("chapter14_tenant_isolation", "chapter14/tenant_isolation.py")
ch15 = load_example("chapter15_permission_models", "chapter15/permission_models.py")
ch16 = load_example(
    "chapter16_security_design_patterns",
    "chapter16/security_design_patterns.py",
)
ch17 = load_example(
    "chapter17_supply_chain_security",
    "chapter17/supply_chain_security.py",
)
ch18 = load_example(
    "chapter18_monitoring_observability",
    "chapter18/monitoring_observability.py",
)
ch19 = load_example(
    "chapter19_governance_compliance",
    "chapter19/governance_compliance.py",
)
ch20 = load_example("chapter20_hitl_controls", "chapter20/hitl_controls.py")


class Chapter12Tests(unittest.TestCase):
    def test_tool_definition_is_authorized_and_defensively_copied(self) -> None:
        tool = ch12.ToolDefinition(
            "read_ticket",
            "Read one ticket",
            "1.0.0",
            {"type": "object", "properties": {"id": {"type": "string"}}},
            "low",
        )
        index = ch12.ToolIndex(
            {tool.name: tool},
            lambda principal, _tool: principal == "alice",
        )
        returned = index.get_definition("alice", "read_ticket")
        returned.input_schema["properties"]["id"]["type"] = "integer"
        fresh = index.get_definition("alice", "read_ticket")
        self.assertEqual(fresh.input_schema["properties"]["id"]["type"], "string")
        with self.assertRaises(ch12.ToolDefinitionDenied):
            index.get_definition("mallory", "read_ticket")


class Chapter13Tests(unittest.TestCase):
    def test_cache_rotates_and_rejects_unsafe_names(self) -> None:
        provider = ch13.DemoProvider()
        now = [0.0]
        cache = ch13.SecretCache(provider, ttl_seconds=10, clock=lambda: now[0])
        first = cache.read("service/api")
        self.assertEqual(first, cache.read("service/api"))
        now[0] = 11.0
        self.assertNotEqual(first.version, cache.read("service/api").version)
        with self.assertRaises(ValueError):
            cache.read("service/../admin")


class Chapter14Tests(unittest.TestCase):
    def test_tenant_boundary_and_cache_partition(self) -> None:
        alice = ch14.extract_tenant_identity(
            {"tenant_id": "tenant-a", "sub": "alice", "role": "user"}
        )
        bob = ch14.extract_tenant_identity(
            {"tenant_id": "tenant-b", "sub": "bob", "role": "user"}
        )
        record = ch14.HandleRecord("record-1", "tenant-a", "alice", 1)
        ch14.authorize_handle_action(record, alice, "read", frozenset({"read"}))
        with self.assertRaises(PermissionError):
            ch14.authorize_handle_action(record, bob, "read", frozenset({"read"}))
        secret = bytes(range(32))
        self.assertNotEqual(
            ch14.tenant_cache_key("tenant-a", "tools/list", secret),
            ch14.tenant_cache_key("tenant-b", "tools/list", secret),
        )


class Chapter15Tests(unittest.TestCase):
    def test_approval_is_bound_and_one_time(self) -> None:
        principal = ch15.Principal("admin", "tenant-a", "admin-1")
        permission = ch15.TieredPermission(
            principal,
            frozenset(
                {
                    ch15.PermissionScope(
                        "admin_export",
                        "archive",
                        "2026-Q3",
                    )
                }
            ),
            ch15.RiskLevel.MEDIUM,
        )
        digest = ch15.build_request_digest(
            "admin_export", "archive", "2026-Q3", {"format": "csv"}
        )
        verifier = ch15.OneTimeApprovalVerifier(
            {
                "grant": ch15.ApprovalGrant(
                    "tenant-a",
                    "admin-1",
                    "admin_export",
                    "archive",
                    "2026-Q3",
                    digest,
                    "transaction_approval",
                )
            }
        )
        allowed = ch15.server_authorization_gate(
            permission,
            "admin_export",
            "archive",
            "2026-Q3",
            ch15.AssuranceLevel.HIGH,
            digest,
            "grant",
            verifier,
        )
        replay = ch15.server_authorization_gate(
            permission,
            "admin_export",
            "archive",
            "2026-Q3",
            ch15.AssuranceLevel.HIGH,
            digest,
            "grant",
            verifier,
        )
        self.assertTrue(allowed.allowed)
        self.assertEqual(replay.reason_code, "invalid_approval_artifact")


class Chapter16Tests(unittest.TestCase):
    def test_identity_profiles_and_service_policy(self) -> None:
        standard = ch16.StandardClaimsExtractor().extract(
            ch16.VerifiedClaims(
                {
                    "tenant_id": "tenant-a",
                    "sub": "agent-1",
                    "roles": ["support"],
                    "scope": "tickets.read",
                },
                "https://id.example.test",
                "tickets-server",
            )
        )
        self.assertIn("tickets.read", standard.scopes)
        with self.assertRaises(PermissionError):
            ch16.authorize_service_call(
                ch16.VerifiedWorkloadIdentity("spiffe://example.test/client"),
                "data-store-readwrite",
            )


class Chapter17Tests(unittest.TestCase):
    def test_manifest_rejects_duplicate_keys_and_incomplete_ci(self) -> None:
        with self.assertRaises(ch17.SecurityError):
            ch17.parse_manifest(b'{"schema_version":"1","schema_version":"1"}')
        decision = ch17.evaluate_ci_gate((), scanner_completed=False)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "scanner_incomplete")


class Chapter18Tests(unittest.TestCase):
    def test_trace_and_sparse_baseline_rules(self) -> None:
        trace_id = ch18.new_trace_id()
        self.assertEqual(ch18.validate_trace_id(trace_id), trace_id)
        with self.assertRaises(ValueError):
            ch18.validate_trace_id("0" * 32)
        self.assertIsNone(
            ch18.check_invocation_spike(99, 0, 5, "actor", "export")
        )
        self.assertIsNotNone(
            ch18.check_invocation_spike(100, 0, 5, "actor", "export")
        )


class Chapter19Tests(unittest.TestCase):
    def test_requester_cannot_approve_own_tool(self) -> None:
        now = datetime.now(timezone.utc)
        registry = ch19.GovernanceRegistry()
        registration = ch19.ToolRegistration(
            "com.example.tool",
            "1.0.0",
            "example",
            "a" * 64,
            "b" * 64,
            ch19.RiskTier.LOW,
            "internal",
            "requester-1",
        )
        registry.register_tool(registration)
        reviewer = ch19.VerifiedReviewer(
            "requester-1",
            frozenset({"tool_approver"}),
            "https://id.example.test",
            now,
            "aal2",
        )
        with self.assertRaises(PermissionError):
            registry.record_approval(
                registration.key,
                reviewer,
                ("evidence://review/1",),
                decision_time=now,
            )


class Chapter20Tests(unittest.TestCase):
    def _context(self) -> object:
        return ch20.InvocationContext(
            qualified_tool="trusted.tickets.export_cases",
            tool_version="2.4.1",
            artifact_sha256="a" * 64,
            schema_sha256="b" * 64,
            tenant_ref="tenant-a",
            actor_ref="requester-1",
            resource_version="records-v7",
            data_classification="confidential",
            item_count=20,
        )

    def test_self_approval_is_denied(self) -> None:
        now = datetime.now(timezone.utc)
        context = self._context()
        request = ch20.create_approval_request(context, {"format": "csv"}, now=now)
        store = ch20.ApprovalStore()
        store.save_request(request)
        requester = ch20.VerifiedApprover(
            "requester-1",
            "tenant-a",
            frozenset({"hitl_approver"}),
            "https://id.example.test",
            now + timedelta(seconds=1),
            "aal2",
        )
        with self.assertRaises(PermissionError):
            store.approve_request(
                request.request_id,
                requester,
                now=now + timedelta(seconds=2),
            )

    def test_grant_is_one_time_and_release_bound(self) -> None:
        now = datetime.now(timezone.utc)
        context = self._context()
        arguments = {"format": "csv"}
        request = ch20.create_approval_request(context, arguments, now=now)
        store = ch20.ApprovalStore()
        store.save_request(request)
        approver = ch20.VerifiedApprover(
            "approver-2",
            "tenant-a",
            frozenset({"hitl_approver"}),
            "https://id.example.test",
            now + timedelta(seconds=1),
            "aal2",
        )
        token = store.approve_request(
            request.request_id,
            approver,
            now=now + timedelta(seconds=2),
        )
        changed_release = ch20.InvocationContext(
            **{
                **context.__dict__,
                "tool_version": "2.4.2",
                "artifact_sha256": "c" * 64,
            }
        )
        with self.assertRaises(PermissionError):
            store.consume(
                token,
                request.request_id,
                changed_release,
                arguments,
                now=now + timedelta(seconds=3),
            )
        store.consume(
            token,
            request.request_id,
            context,
            arguments,
            now=now + timedelta(seconds=3),
        )
        with self.assertRaises(PermissionError):
            store.consume(
                token,
                request.request_id,
                context,
                arguments,
                now=now + timedelta(seconds=4),
            )


if __name__ == "__main__":
    unittest.main()
