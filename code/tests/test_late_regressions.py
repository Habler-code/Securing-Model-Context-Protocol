"""Offline regression tests for the security boundaries in Chapters 12–20.

Run from code/: python -m unittest discover -s tests -v
No network access, real credentials, production services, or database changes.
"""

from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import StringIO
import json
from threading import Barrier, Thread
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from test_examples import ch12, ch13, ch14, ch15, ch16, ch17, ch18, ch19, ch20


NOW = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)


class BoundedRemoteTests(unittest.TestCase):
    def test_body_limit_and_chunk_type(self):
        self.assertEqual(ch12.read_bounded_body((b"ab", b"c"), 3), b"abc")
        self.assertEqual(ch12.read_bounded_body((), 1), b"")
        with self.assertRaises(ValueError):
            ch12.read_bounded_body((b"ab", b"cd"), 3)
        for invalid in (0, -1, True, 1.5):
            with self.subTest(limit=invalid), self.assertRaises(ValueError):
                ch12.read_bounded_body((), invalid)
        with self.assertRaises(TypeError):
            ch12.read_bounded_body(("text",), 20)

    def test_hidden_definitions_and_registry_snapshot(self):
        schema = {"type": "object", "properties": {"id": {"type": "string"}}}
        tool = ch12.ToolDefinition("read", "Read one item", "1", schema, "low")
        index = ch12.ToolIndex({"read": tool}, lambda actor, _tool: actor == "allowed")
        schema["properties"]["id"]["type"] = "integer"
        copy = index.get_definition("allowed", "read")
        self.assertEqual(copy.input_schema["properties"]["id"]["type"], "string")
        self.assertEqual(index.list_summaries("denied"), [])
        for name in ("read", "missing"):
            with self.assertRaises(ch12.ToolDefinitionDenied):
                index.get_definition("denied", name)


class SecretCacheRegressions(unittest.TestCase):
    def test_latest_string_cache_interface_and_clear_memory(self):
        class StringProvider:
            calls = 0

            def get_secret(self, name):
                self.calls += 1
                return f"synthetic-value-{self.calls}"

        provider = StringProvider()
        cache = ch13.ThreadSafeSecretCache(provider, ttl_seconds=30)
        first = cache.read("postgres_agent_role")
        self.assertEqual(first, cache.read("postgres_agent_role"))
        self.assertEqual(provider.calls, 1)
        cache.clear_memory("postgres_agent_role")
        self.assertNotEqual(first, cache.read("postgres_agent_role"))
        cache.clear_memory()
        self.assertEqual(len(cache._implementation._cache), 0)
        mock = ch13.MockVaultProvider()
        self.assertEqual(mock.get_secret("one"), mock.get_secret("one"))

    def test_capacity_eviction_and_expired_pruning(self):
        now = [0.0]
        cache = ch13.SecretCache(ch13.DemoProvider(), 10, clock=lambda: now[0], max_entries=2)
        cache.read("one")
        cache.read("two")
        cache.read("one")
        cache.read("three")
        self.assertEqual(set(cache._cache), {"one", "three"})
        now[0] = 11
        cache.read("four")
        self.assertEqual(set(cache._cache), {"four"})

    def test_provider_failure_never_serves_expired_data_or_exception_secret(self):
        class Provider:
            failed = False

            def get_secret(self, _name):
                if self.failed:
                    raise RuntimeError("sensitive-provider-payload")
                return ch13.ProviderSecret("synthetic-value", "v1")

        now = [0.0]
        provider = Provider()
        cache = ch13.SecretCache(provider, 1, clock=lambda: now[0])
        cache.read("demo")
        provider.failed = True
        now[0] = 2.0
        with self.assertLogs(ch13.LOGGER, level="WARNING") as logs:
            with self.assertRaises(ch13.SecretUnavailable) as raised:
                cache.read("demo")
        self.assertNotIn("sensitive-provider-payload", str(raised.exception))
        self.assertNotIn("sensitive-provider-payload", " ".join(logs.output))
        self.assertNotIn("synthetic-value", repr(ch13.ProviderSecret("synthetic-value", "v1")))

    def test_refresh_and_policy_validation(self):
        cache = ch13.SecretCache(ch13.DemoProvider())
        self.assertNotEqual(cache.read("demo").version, cache.refresh("demo").version)
        for invalid in (0, -1, 301, float("nan"), True):
            with self.subTest(ttl=invalid), self.assertRaises(ValueError):
                ch13.SecretCache(ch13.DemoProvider(), invalid)
        for name in ("", "../x", "a//b", "a/", "a/../b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                cache.read(name)


class TenantAdapterRegressions(unittest.TestCase):
    def test_private_cache_binds_caller_and_policy(self):
        identity = ch14.TenantIdentity("tenant-a", "alice", "user")
        secret = bytes(range(32))  # Synthetic test bytes, never a deployment key.

        def key(actor=identity, policy="policy-v1"):
            return ch14.private_cache_key(actor, "server", "tools/list", {}, policy, secret)

        self.assertNotEqual(key(), key(replace(identity, user_id="bob")))
        self.assertNotEqual(key(), key(replace(identity, tenant_id="tenant-b")))
        self.assertNotEqual(key(), key(policy="policy-v2"))

    def test_query_adapter_uses_transaction_and_bound_parameters(self):
        class Connection:
            def __init__(self):
                self.calls = []
                self.active = False

            def transaction(self):
                return self

            def __enter__(self):
                self.active = True

            def __exit__(self, *_args):
                self.active = False

            def execute(self, sql, params):
                self.calls.append((sql, params, self.active))
                return self

            def fetchone(self):
                return ("doc-1", "Example", "Synthetic text")

        connection = Connection()
        document_id = "x' OR '1'='1"
        identity = ch14.TenantIdentity("tenant-a", "alice", "user")
        row = ch14.fetch_document(connection, identity, document_id)
        self.assertEqual(row[0], "doc-1")
        self.assertTrue(all(active for _, _, active in connection.calls))
        self.assertEqual(connection.calls[0][1], ("tenant-a",))
        self.assertEqual(connection.calls[1][1], ("tenant-a", document_id))
        self.assertNotIn(document_id, connection.calls[1][0])

    def test_audit_contains_references_without_raw_payload(self):
        with self.assertLogs(ch14.LOGGER, level="INFO") as logs:
            ch14.audit_tool_decision("tenant-ref", "actor-ref", "read", "deny", "scope_denied")
        self.assertEqual(logs.records[0].tenant_ref, "tenant-ref")
        self.assertEqual(logs.records[0].reason_code, "scope_denied")


class PermissionRegressions(unittest.TestCase):
    def test_latest_chapter_mechanism_names_keep_server_approval_separate(self):
        user = ch15.Principal("user", "tenant-a", "agent")
        admin = ch15.Principal("admin", "tenant-a", "admin")
        signals = ch15.TrustSignals(1, True, 0.1, 0)
        self.assertEqual(ch15.compute_trust_level(signals), "high")
        ch15.authorize_tool(user, "update_status")
        ch15.authorize_with_trust(user, "update_status", "high")
        self.assertTrue(ch15.host_policy_gate(user, "update_status", "high"))
        self.assertFalse(ch15.host_policy_gate(admin, "admin_export", "high"))
        with self.assertRaises(PermissionError):
            ch15.authorize_tool(admin, "admin_export")
        ch15.authorize_tool(admin, "admin_export", has_approval=True)
        permission = ch15.TieredPermission(admin, frozenset({ch15.PermissionScope("admin_export", "archive", "q1")}), ch15.RiskLevel.MEDIUM)
        final = ch15.server_authorization_gate(permission, "admin_export", "archive", "q1", ch15.AssuranceLevel.HIGH, "digest", None, ch15.OneTimeApprovalVerifier({}))
        self.assertFalse(final)
        self.assertEqual(final.reason, "approval_required")
        self.assertEqual(final.required_approvals, ["transaction_approval"])

    def test_assurance_cannot_expand_role(self):
        viewer = ch15.Principal("viewer", "tenant-a", "viewer")
        self.assertFalse(ch15.authorize_with_assurance(viewer, "admin_export", ch15.AssuranceLevel.HIGH).allowed)
        admin = ch15.Principal("admin", "tenant-a", "admin")
        self.assertEqual(ch15.authorize_with_assurance(admin, "admin_export", ch15.AssuranceLevel.LOW).reason_code, "step_up_required")
        self.assertFalse(ch15.authorize_with_assurance(admin, "search", 3).allowed)

    def test_invalid_signals_and_nonfinite_digest_are_rejected(self):
        for kwargs in ({"session_age_minutes": True}, {"anomaly_score": float("nan")}, {"failed_attempts_recent": 1.5}):
            fields = dict(session_age_minutes=1, mfa_verified=True, anomaly_score=0.1, failed_attempts_recent=0)
            fields.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ch15.TrustSignals(**fields)
        with self.assertRaises(ValueError):
            ch15.build_request_digest("read", "doc", "1", {"x": float("nan")})

    def test_verifier_rejects_changed_actor_scope_and_digest(self):
        principal = ch15.Principal("admin", "tenant-a", "admin")
        grant = ch15.ApprovalGrant("tenant-a", "admin", "admin_export", "archive", "q1", "digest", "transaction_approval")
        verifier = ch15.OneTimeApprovalVerifier({"fixture": grant})
        fields = dict(principal=principal, tool="admin_export", resource_type="archive", resource_id="q1", request_digest="digest", approval_purpose="transaction_approval")
        mutations = dict(principal=replace(principal, tenant_id="tenant-b"), tool="delete_project", resource_id="q2", request_digest="changed", approval_purpose="step_up")
        for name, value in mutations.items():
            with self.subTest(name=name):
                self.assertFalse(verifier.verify_and_consume("fixture", **{**fields, name: value}))
        self.assertTrue(verifier.verify_and_consume("fixture", **fields))


class DefenseLayerRegressions(unittest.TestCase):
    def test_latest_service_request_and_context_artifact_call_forms(self):
        identity = ch16.StandardClaimsExtractor().extract({"tenant_id": "tenant-a", "sub": "agent", "roles": ["support"], "scope": "tickets.read"})
        request = ch16.VerifiedServiceRequest("mcp-client", "mcp-server", identity, "tools/call")
        ch16.authorize_service_call(request)
        with self.assertRaises(PermissionError):
            ch16.authorize_service_call(replace(request, receiving_service="external-api"))
        context = ch16.PolicyContext("tenant-a", "agent", "session", "export", "cases", "digest", "high", 0.9, "step:tenant-a:agent:session", "approve:tenant-a:agent:digest:transaction_approval")
        verifier = ch16.DemoContextVerifier()
        self.assertTrue(ch16.decide(context, verifier).allowed)
        self.assertEqual(ch16.decide(context, verifier).reason, "invalid_approval_artifact")

    def test_required_layers_cannot_be_omitted_or_duplicated(self):
        good = tuple(ch16.LayeredCheckResult(name, True, "passed") for name in sorted(ch16.REQUIRED_DEFENSE_LAYERS))
        ch16.enforce_defense_layers(good)
        for results in ((), good[:-1], (*good, good[0])):
            with self.subTest(results=results), self.assertRaises(PermissionError):
                ch16.enforce_defense_layers(results)

    def test_nonboolean_and_exception_checks_fail_closed(self):
        def broken():
            raise RuntimeError("synthetic failure")

        results = ch16.run_defense_layers((("prevent", lambda: "yes", "denied"), ("detect", broken, "denied")))
        self.assertEqual([r.reason_code for r in results], ["invalid_check_result", "check_error"])
        self.assertTrue(all(r.passed is False for r in results))
        with self.assertRaises(ValueError):
            ch16.run_defense_layers((("prevent", lambda: True, "x"), ("prevent", lambda: True, "x")))

    def test_claim_profiles_and_service_allowlist(self):
        standard = ch16.StandardClaimsExtractor().extract(ch16.VerifiedClaims({"tenant_id": "t", "sub": "u", "roles": ["support"], "scope": "tickets.read"}, "issuer", "audience"))
        namespaced = ch16.NamespacedClaimsExtractor().extract(ch16.VerifiedClaims({ch16.NamespacedClaimsExtractor.TENANT_CLAIM: "t", ch16.NamespacedClaimsExtractor.ROLES_CLAIM: ["support"], "sub": "u", "scope": "tickets.read"}, "other-issuer", "audience"))
        self.assertEqual(standard, namespaced)
        with self.assertRaises(PermissionError):
            ch16.StandardClaimsExtractor().extract(ch16.VerifiedClaims({"tenant_id": "t", "sub": "u", "roles": "admin"}, "issuer", "audience"))
        with self.assertRaises(PermissionError):
            ch16.authorize_service_call(ch16.VerifiedWorkloadIdentity("unknown"), "mcp-server")


class SupplyChainRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_pem = cls.private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def fixture(self):
        package = b"synthetic package"
        sbom = b'{"example":"digest-binding-only"}'
        manifest = json.dumps(dict(schema_version="1", name="server", version="1", publisher="publisher", key_id="key", artifact_sha256=sha256(package).hexdigest(), sbom_sha256=sha256(sbom).hexdigest()), separators=(",", ":")).encode()
        signature = self.private_key.sign(manifest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        verifier = ch17.ServerVerifier({("publisher", "key"): self.public_pem})
        return manifest, signature, package, sbom, verifier

    def test_signed_package_and_sbom_binding(self):
        manifest, signature, package, sbom, verifier = self.fixture()
        trusted = ch17.verify_package(manifest, signature, package, verifier, expected_name="server", expected_version="1")
        ch17.verify_bound_sbom(trusted, sbom)
        with self.assertRaises(ch17.SecurityError):
            ch17.verify_package(manifest, signature, package + b"changed", verifier, expected_name="server", expected_version="1")
        with self.assertRaises(ch17.SecurityError):
            verifier.verify_signed_manifest(manifest, signature[:-1] + bytes([signature[-1] ^ 1]))
        with self.assertRaises(ch17.SecurityError):
            ch17.verify_bound_sbom(trusted, sbom + b"changed")
        with self.assertRaises(ch17.SecurityError):
            ch17.verify_package(manifest, signature, package, verifier, expected_name="other", expected_version="1")
        with self.assertRaises(ch17.SecurityError):
            verifier.verify_signed_manifest(manifest, b"x" * 100_000)

    def test_weak_keys_and_invalid_metadata_rejected(self):
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaises(ValueError):
            ch17.ServerVerifier({("p", "k"): weak})
        with self.assertRaises(ValueError):
            ch17.DependencyStatus("dep", "1", "2", "CRITICAL", True)
        with self.assertRaises(ValueError):
            ch17.DependencyStatus("dep", "1", None, "high", True)
        with self.assertRaises(ValueError):
            ch17.PinnedDependency("dep", "1", "invalid")
        with self.assertRaises(ch17.SecurityError):
            ch17.parse_manifest(b" " * 65_537)

    def test_ci_and_lockfile_reject_drift(self):
        result = ch17.ScanResult("scanner", "critical", "rule", "example.py", 1)
        self.assertFalse(ch17.evaluate_ci_gate((result,), scanner_completed=True).allowed)
        self.assertFalse(ch17.evaluate_ci_gate((), scanner_completed="yes").allowed)
        archive = b"archive"
        locked = (ch17.PinnedDependency("My_Package", "1", sha256(archive).hexdigest()),)
        self.assertEqual(ch17.verify_lockfile_integrity(locked, {"my-package": ("1", archive)}), ())
        self.assertTrue(ch17.verify_lockfile_integrity(locked, {"my-package": ("2", b"changed"), "extra": ("1", b"extra")}))
        self.assertTrue(ch17.verify_lockfile_integrity((*locked, *locked), {}))


class ObservabilityRegressions(unittest.TestCase):
    def test_latest_audit_contract_rejects_bad_timestamp_and_whitespace(self):
        event = ch18.ToolAuditEvent("event", ch18.new_trace_id(), "request", "tenant-ref", "actor-ref", "server", "read", "low", "deny", "denied", "input-ref")
        for timestamp in ("not-a-time", "2026-10-22T12:00:00"):
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                replace(event, occurred_at=timestamp)
        with self.assertRaises(ValueError):
            replace(event, actor_ref=" ")
        with self.assertRaises(ValueError):
            replace(event, reason_code="x" * (ch18.MAX_AUDIT_FIELD_CHARS + 1))

    def test_trace_generator_retries_three_times_then_fails_closed(self):
        with patch.object(ch18.secrets, "token_hex", return_value="0" * 32) as generator:
            with self.assertRaises(RuntimeError):
                ch18.new_trace_id()
            self.assertEqual(generator.call_count, 3)
        with patch.object(ch18.secrets, "token_hex", side_effect=["0" * 32, "a" * 32]):
            self.assertEqual(ch18.new_trace_id(), "a" * 32)
        self.assertTrue(ch18.is_valid_trace_id("a" * 32))
        self.assertFalse(ch18.is_valid_trace_id(None))

    def test_ndjson_escapes_newlines_and_emits_one_record(self):
        event = ch18.ToolAuditEvent("event", ch18.new_trace_id(), "request", "tenant-ref", "actor-ref", "server", "read\nforged", "low", "deny", "denied", "input-ref")
        capture = StringIO()
        with redirect_stdout(capture):
            ch18.emit_audit_event(event)
        self.assertEqual(len(capture.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(capture.getvalue())["tool_alias"], "read\nforged")

    def test_metric_capacity_and_types(self):
        metrics = ch18.ToolUsageMetrics(max_keys=1)
        metrics.record_invocation("actor", "read", True, 10)
        with self.assertRaises(ValueError):
            metrics.record_invocation("other", "read", True)
        self.assertEqual(metrics.dropped_series, 1)
        self.assertEqual(len(metrics.last_invocation), 1)
        with self.assertRaises(ValueError):
            metrics.record_invocation("actor", "read", "yes")

    def test_rules_and_trace_types(self):
        for invalid in (None, "0" * 32, "A" * 32, "a" * 31):
            with self.subTest(trace=invalid), self.assertRaises(ValueError):
                ch18.validate_trace_id(invalid)
        for count in (True, float("nan"), -1):
            with self.subTest(count=count), self.assertRaises(ValueError):
                ch18.check_invocation_spike(count, 5, 5, "actor", "read")
        with self.assertRaises(ValueError):
            ch18.SpikeRule(minimum_baseline_count=0)
        self.assertIsNone(ch18.check_invocation_spike(49, 5, 5, "a", "read"))
        self.assertIsNotNone(ch18.check_invocation_spike(50, 5, 5, "a", "read"))


class GovernanceRegressions(unittest.TestCase):
    def registration(self, **changes):
        values = dict(qualified_name="example.tool", version="1", publisher="publisher", artifact_sha256="a" * 64, schema_sha256="b" * 64, risk_tier=ch19.RiskTier.HIGH, data_classification="restricted", requested_by="requester")
        values.update(changes)
        return ch19.ToolRegistration(**values)

    def reviewer(self, subject="reviewer", roles=frozenset({"tool_approver"}), **changes):
        values = dict(subject_ref=subject, roles=roles, identity_issuer="https://id.example.test", authenticated_at=NOW, assurance_level="aal2")
        values.update(changes)
        return ch19.VerifiedReviewer(**values)

    def test_risk_and_status_must_be_enum_values(self):
        for invalid in ("high", None, 3):
            with self.subTest(risk=invalid), self.assertRaises(ValueError):
                self.registration(risk_tier=invalid)
        with self.assertRaises(ValueError):
            self.registration(status="pending")

    def test_high_risk_needs_two_independent_current_reviewers(self):
        registry = ch19.GovernanceRegistry()
        tool = self.registration()
        registry.register_tool(tool)
        first = registry.record_approval(tool.key, self.reviewer(), ("evidence://one",), decision_time=NOW)
        self.assertEqual(first.status, ch19.ApprovalStatus.PENDING)
        with self.assertRaises(PermissionError):
            registry.assert_enabled(tool.key)
        with self.assertRaises(PermissionError):
            registry.record_approval(tool.key, self.reviewer(), ("evidence://duplicate",), decision_time=NOW)
        for reviewer in (self.reviewer("stale", authenticated_at=NOW - timedelta(seconds=301)), self.reviewer("weak", assurance_level="aal1"), self.reviewer("requester")):
            with self.subTest(reviewer=reviewer.subject_ref), self.assertRaises(PermissionError):
                registry.record_approval(tool.key, reviewer, ("evidence://bad",), decision_time=NOW)
        second = self.reviewer("security", frozenset({"tool_approver", "security_approver"}))
        registry.record_approval(tool.key, second, ("evidence://two",), decision_time=NOW)
        self.assertEqual(registry.assert_enabled(tool.key).status, ch19.ApprovalStatus.APPROVED)

    def test_evidence_currency_and_retention_validation(self):
        evidence = ch19.ComplianceEvidence("control", "test", "evidence://test", "owner", NOW, NOW + timedelta(seconds=10), "a" * 64)
        self.assertTrue(evidence.is_current(NOW))
        self.assertFalse(evidence.is_current(NOW + timedelta(seconds=11)))
        policy = ch19.DataRetentionPolicy("p", "audit", 30, "purge", "business policy", "owner", True)
        ch19.validate_retention_policy(policy)
        with self.assertRaises(ValueError):
            ch19.validate_retention_policy(replace(policy, max_retention_days=True))

    def test_concurrent_reviews_preserve_both_votes_and_example_policies(self):
        registry = ch19.GovernanceRegistry()
        tool = self.registration()
        registry.register_tool(tool)
        reviewers = (self.reviewer("first"), self.reviewer("security", frozenset({"tool_approver", "security_approver"})))
        barrier = Barrier(2)
        errors = []

        def review(reviewer):
            barrier.wait()
            try:
                registry.record_approval(tool.key, reviewer, ("evidence://synthetic",), decision_time=NOW)
            except Exception as exc:
                errors.append(exc)

        workers = [Thread(target=review, args=(reviewer,)) for reviewer in reviewers]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(registry.assert_enabled(tool.key).approvals), 2)
        self.assertEqual(len(ch19.EXAMPLE_RETENTION_POLICIES), 2)
        for policy in ch19.EXAMPLE_RETENTION_POLICIES:
            ch19.validate_retention_policy(policy)


class HumanApprovalRegressions(unittest.TestCase):
    def context(self):
        return ch20.InvocationContext("trusted.tickets.export_cases", "1", "a" * 64, "b" * 64, "tenant-a", "requester", "resource-v1", "restricted", 5, (ch20.DelegationHop("requester", "agent", "export"),))

    def approver(self, subject="reviewer", roles=frozenset({"hitl_approver"})):
        return ch20.VerifiedApprover(subject, "tenant-a", roles, "https://id.example.test", NOW + timedelta(seconds=1), "aal2")

    def approved(self):
        context = self.context()
        arguments = {"recipient": "synthetic@example.test", "count": 5}
        request = ch20.create_approval_request(context, arguments, "Review the exact synthetic export.", now=NOW)
        store = ch20.ApprovalStore()
        store.save_request(request)
        token = store.approve_request(request.request_id, self.approver(), now=NOW + timedelta(seconds=2))
        return context, arguments, request, store, token

    def test_all_governed_context_mutations_deny(self):
        context, arguments, request, store, token = self.approved()
        mutations = dict(tool_version="2", artifact_sha256="c" * 64, schema_sha256="d" * 64, tenant_ref="tenant-b", actor_ref="other", resource_version="resource-v2", data_classification="confidential", item_count=6, external_side_effect=True, privilege_change=True, irreversible=True, delegation_chain=(ch20.DelegationHop("requester", "different-agent", "export"),))
        for field, value in mutations.items():
            with self.subTest(field=field), self.assertRaises(PermissionError):
                store.consume(token, request.request_id, replace(context, **{field: value}), arguments, now=NOW + timedelta(seconds=3))
        with self.assertRaises(PermissionError):
            store.consume(token, request.request_id, context, {**arguments, "count": 6}, now=NOW + timedelta(seconds=3))
        store.consume(token, request.request_id, context, arguments, now=NOW + timedelta(seconds=3))

    def test_not_yet_valid_expiry_and_atomic_replay(self):
        context, arguments, request, store, token = self.approved()
        for time in (NOW + timedelta(seconds=1), NOW + timedelta(seconds=302)):
            with self.subTest(time=time), self.assertRaises(PermissionError):
                store.consume(token, request.request_id, context, arguments, now=time)
        ch20.assert_single_concurrent_redemption(store, token, request.request_id, context, arguments, now=NOW + timedelta(seconds=3))

    def test_latest_canonical_json_risk_and_at_redemption_api(self):
        context, arguments, request, store, token = self.approved()
        canonical = ch20.canonicalize_arguments(arguments)
        with self.assertRaises(PermissionError):
            store.consume(token, request.request_id, context, risk_tier=ch20.RiskTier.LOW, arguments_json=canonical, at=NOW + timedelta(seconds=3))
        with self.assertRaises(ValueError):
            store.consume(token, request.request_id, context, risk_tier=ch20.RiskTier.HIGH, arguments_json=json.dumps(arguments), at=NOW + timedelta(seconds=3))
        grant = store.consume(token, request.request_id, context, ch20.RiskTier.HIGH, canonical, NOW + timedelta(seconds=3))
        self.assertEqual(grant.risk_tier, "high")

    def test_roles_and_emergency_tools_require_exact_immutable_sets(self):
        for roles in ("not_hitl_approver", ["hitl_approver"], {"hitl_approver"}, frozenset({1}), frozenset({" "}), frozenset({"x" * 129})):
            with self.subTest(roles=roles), self.assertRaises(ValueError):
                self.approver(roles=roles)
        context = self.context()
        for tools in (context.qualified_tool, [context.qualified_tool], {context.qualified_tool}, frozenset({1}), frozenset({" "}), frozenset({"x" * 257})):
            with self.subTest(tools=tools), self.assertRaises(ValueError):
                ch20.BreakGlassPolicy(tools, 10)
        store = ch20.BreakGlassStore(ch20.BreakGlassPolicy(frozenset({context.qualified_tool + ".other"}), 10))
        with self.assertRaises(PermissionError):
            store.create_request(context, {}, "INC-synthetic", now=NOW)
        request = ch20.create_approval_request(context, {}, now=NOW)
        approval_store = ch20.ApprovalStore()
        approval_store.save_request(request)
        with self.assertRaises(PermissionError):
            approval_store.approve_request(request.request_id, self.approver(roles=frozenset({"not_hitl_approver"})), at=NOW + timedelta(seconds=2))

    def test_approve_at_alias_audit_fields_and_fixed_request_lifetime(self):
        context = self.context()
        request = ch20.create_approval_request(context, {}, now=NOW)
        store = ch20.ApprovalStore()
        store.save_request(request)
        approver = self.approver()
        with self.assertRaises(ValueError):
            store.approve_request(request.request_id, approver, at=NOW + timedelta(seconds=2), now=NOW + timedelta(seconds=2))
        token = store.approve_request(request.request_id, approver, NOW + timedelta(seconds=2))
        grant = store.consume(token, request.request_id, context, {}, at=NOW + timedelta(seconds=3))
        self.assertEqual(grant.approver_issuer, approver.identity_issuer)
        self.assertEqual(grant.approver_assurance_level, approver.assurance_level)
        self.assertEqual(grant.approver_authenticated_at, approver.authenticated_at)
        delayed = replace(request, request_id="delayed", approval_deadline=NOW + timedelta(seconds=600))
        store.save_request(delayed)
        fresh = replace(approver, authenticated_at=NOW + timedelta(seconds=300))
        with self.assertRaises(PermissionError):
            store.approve_request(delayed.request_id, fresh, at=NOW + timedelta(seconds=301))

    def test_token_collision_retries_do_not_overwrite_existing_grant(self):
        context = self.context()
        requests = [ch20.create_approval_request(context, {"case": n}, now=NOW) for n in range(3)]
        store = ch20.ApprovalStore()
        for request in requests:
            store.save_request(request)
        with patch.object(ch20.secrets, "token_urlsafe", side_effect=["collision-fixture", "collision-fixture", "unique-fixture"]):
            first = store.approve_request(requests[0].request_id, self.approver(), at=NOW + timedelta(seconds=2))
            second = store.approve_request(requests[1].request_id, self.approver(), at=NOW + timedelta(seconds=2))
        self.assertNotEqual(first, second)
        self.assertEqual(len(store._grants), 2)
        with patch.object(ch20.secrets, "token_urlsafe", return_value="collision-fixture") as generator:
            with self.assertRaises(RuntimeError):
                store.approve_request(requests[2].request_id, self.approver(), at=NOW + timedelta(seconds=2))
            self.assertEqual(generator.call_count, 3)
        self.assertNotIn(requests[2].request_id, store._decided_requests)
        self.assertEqual(len(store._grants), 2)

    def test_enforcement_returns_immutable_arguments_and_fatigue_thresholds(self):
        context, arguments, request, store, token = self.approved()
        with self.assertRaises(PermissionError):
            ch20.enforce_hitl_policy(context, arguments, store, now=NOW + timedelta(seconds=3))
        frozen = ch20.enforce_hitl_policy(context, arguments, store, token, request.request_id, now=NOW + timedelta(seconds=3))
        arguments["count"] = 999
        self.assertEqual(json.loads(frozen)["count"], 5)
        expected = {4: ch20.FatigueAction.CONTINUE, 5: ch20.FatigueAction.REQUIRE_BATCH_REVIEW, 9: ch20.FatigueAction.REQUIRE_BATCH_REVIEW, 10: ch20.FatigueAction.PAUSE_SESSION}
        for count, action in expected.items():
            self.assertEqual(ch20.evaluate_approval_fatigue(count).action, action)

    def test_break_glass_binds_actor_release_scope_and_time(self):
        context = self.context()
        arguments = {"count": 5}
        store = ch20.BreakGlassStore(ch20.BreakGlassPolicy(frozenset({context.qualified_tool}), 10))
        request = store.create_request(context, arguments, "INC-synthetic", now=NOW)
        commander = self.approver("commander", frozenset({"incident_commander"}))
        security = self.approver("security", frozenset({"security_duty_officer"}))
        store.authorize(request.request_id, commander, now=NOW + timedelta(seconds=2))
        with self.assertRaises(PermissionError):
            store.consume(request.request_id, context, arguments, now=NOW + timedelta(seconds=3))
        store.authorize(request.request_id, security, now=NOW + timedelta(seconds=2))
        for field, value in dict(actor_ref="other", tool_version="2", artifact_sha256="c" * 64, schema_sha256="d" * 64, item_count=1000, delegation_chain=()).items():
            with self.subTest(field=field), self.assertRaises(PermissionError):
                store.consume(request.request_id, replace(context, **{field: value}), arguments, now=NOW + timedelta(seconds=3))
        with self.assertRaises(PermissionError):
            store.consume(request.request_id, context, arguments, now=NOW + timedelta(seconds=1))
        store.consume(request.request_id, context, arguments, now=NOW + timedelta(seconds=3))
        with self.assertRaises(PermissionError):
            store.consume(request.request_id, context, arguments, now=NOW + timedelta(seconds=4))

    def test_invalid_classification_loops_and_rationale_rejected(self):
        context = self.context()
        for values in ({"data_classification": "restriced"}, {"item_count": True}, {"external_side_effect": "yes"}, {"delegation_chain": context.delegation_chain * 2}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                replace(context, **values)
        with self.assertRaises(ValueError):
            ch20.create_approval_request(context, {}, "", now=NOW)

    def test_approval_identity_and_request_deadline(self):
        context = self.context()
        request = ch20.create_approval_request(context, {}, now=NOW)
        store = ch20.ApprovalStore()
        store.save_request(request)
        invalid = (
            replace(self.approver(), tenant_ref="tenant-b"),
            replace(self.approver(), assurance_level="aal1"),
            replace(self.approver(), roles=frozenset()),
            replace(self.approver(), authenticated_at=NOW - timedelta(seconds=1)),
        )
        for approver in invalid:
            with self.subTest(approver=approver), self.assertRaises(PermissionError):
                store.approve_request(request.request_id, approver, now=NOW + timedelta(seconds=2))
        with self.assertRaises(PermissionError):
            store.approve_request(request.request_id, self.approver(), now=NOW + timedelta(seconds=300))

    def test_emergency_expiry_self_approval_and_duplicates(self):
        context = self.context()
        store = ch20.BreakGlassStore(ch20.BreakGlassPolicy(frozenset({context.qualified_tool}), 10))
        request = store.create_request(context, {}, "INC-synthetic", now=NOW)
        commander = self.approver("commander", frozenset({"incident_commander"}))
        with self.assertRaises(PermissionError):
            store.authorize(request.request_id, replace(commander, subject_ref=context.actor_ref), now=NOW + timedelta(seconds=2))
        store.authorize(request.request_id, commander, now=NOW + timedelta(seconds=2))
        with self.assertRaises(PermissionError):
            store.authorize(request.request_id, commander, now=NOW + timedelta(seconds=2))
        with self.assertRaises(PermissionError):
            store.consume(request.request_id, context, {}, now=NOW + timedelta(seconds=300))


if __name__ == "__main__":
    unittest.main()
