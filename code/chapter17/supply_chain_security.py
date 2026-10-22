"""Runnable examples for Chapter 17: securing the MCP supply chain."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class SecurityError(RuntimeError):
    """Raised when supply-chain evidence fails policy."""


@dataclass(frozen=True)
class PackageManifest:
    schema_version: str
    name: str
    version: str
    publisher: str
    key_id: str
    artifact_sha256: str
    sbom_sha256: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SecurityError("Manifest contains a duplicate key")
        result[key] = value
    return result


def parse_manifest(manifest_bytes: bytes) -> PackageManifest:
    """Parse one strict manifest schema without reserializing it."""
    if not isinstance(manifest_bytes, bytes) or len(manifest_bytes) > 65_536:
        raise SecurityError("Manifest exceeds the byte limit or has an invalid type")
    try:
        text = manifest_bytes.decode("utf-8")
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityError("Manifest is not valid UTF-8 JSON") from exc

    required = {
        "schema_version",
        "name",
        "version",
        "publisher",
        "key_id",
        "artifact_sha256",
        "sbom_sha256",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise SecurityError("Manifest schema does not match version 1")
    if any(not isinstance(data[field], str) or not data[field] for field in required):
        raise SecurityError("Manifest fields must be non-empty strings")
    if data["schema_version"] != "1":
        raise SecurityError("Unsupported manifest schema version")

    for digest_field in ("artifact_sha256", "sbom_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", data[digest_field]):
            raise SecurityError(f"Invalid digest field: {digest_field}")
    return PackageManifest(**data)


class ServerVerifier:
    """Verify signed manifest bytes against reviewed publisher keys."""

    def __init__(self, trusted_keys: dict[tuple[str, str], bytes]) -> None:
        self._keys: dict[tuple[str, str], RSAPublicKey] = {}
        for identity, key_pem in trusted_keys.items():
            key = serialization.load_pem_public_key(key_pem)
            if not isinstance(key, RSAPublicKey):
                raise ValueError("This verifier accepts only RSA public keys")
            if key.key_size < 2048:
                raise ValueError("RSA verification keys must contain at least 2048 bits")
            self._keys[identity] = key

    def verify_signed_manifest(
        self, manifest_bytes: bytes, signature: bytes
    ) -> PackageManifest:
        """Return trusted metadata only after signature verification."""
        untrusted_manifest = parse_manifest(manifest_bytes)
        identity = (untrusted_manifest.publisher, untrusted_manifest.key_id)
        public_key = self._keys.get(identity)
        if public_key is None:
            raise SecurityError("Manifest uses an untrusted publisher key")
        if not isinstance(signature, bytes) or len(signature) != public_key.key_size // 8:
            raise SecurityError("RSA signature has an invalid byte length")
        try:
            public_key.verify(
                signature,
                manifest_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise SecurityError("Manifest signature is invalid") from exc
        return untrusted_manifest


def verify_package(
    manifest_bytes: bytes,
    signature: bytes,
    package_content: bytes,
    verifier: ServerVerifier,
    *,
    expected_name: str,
    expected_version: str,
) -> PackageManifest:
    """Verify signed metadata and the artifact bytes it identifies."""
    manifest = verifier.verify_signed_manifest(manifest_bytes, signature)
    if manifest.name != expected_name or manifest.version != expected_version:
        raise SecurityError("Manifest identifies an unexpected release")
    measured = hashlib.sha256(package_content).hexdigest()
    if not hmac.compare_digest(measured, manifest.artifact_sha256):
        raise SecurityError("Artifact digest does not match signed manifest")
    return manifest


def verify_bound_sbom(manifest: PackageManifest, sbom_bytes: bytes) -> None:
    """Verify that these SBOM bytes are the ones named by the manifest."""
    measured = hashlib.sha256(sbom_bytes).hexdigest()
    if not hmac.compare_digest(measured, manifest.sbom_sha256):
        raise SecurityError("SBOM digest does not match signed manifest")


VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


@dataclass(frozen=True)
class ScanResult:
    tool: str
    severity: str
    rule_id: str
    file_path: str
    line_number: int

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError("Unknown scanner severity")
        if self.line_number < 1:
            raise ValueError("line_number must be positive")


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason_code: str
    blocking_findings: tuple[ScanResult, ...] = ()


def evaluate_ci_gate(
    scan_results: tuple[ScanResult, ...],
    *,
    scanner_completed: bool,
    fail_on: frozenset[str] = frozenset({"critical", "high"}),
) -> GateDecision:
    """Evaluate one required scanner's normalized output."""
    if not fail_on.issubset(VALID_SEVERITIES):
        raise ValueError("Gate contains an unknown severity")
    if not isinstance(scanner_completed, bool):
        return GateDecision(False, "invalid_scanner_status")
    if not scanner_completed:
        return GateDecision(False, "scanner_incomplete")
    blocking = tuple(
        result for result in scan_results if result.severity in fail_on
    )
    if blocking:
        return GateDecision(False, "blocking_findings", blocking)
    return GateDecision(True, "scanner_policy_passed")


@dataclass(frozen=True)
class ServerDescriptor:
    name: str
    publisher: str
    key_id: str
    version: str
    protocol_versions: tuple[str, ...]
    extensions: tuple[str, ...]
    artifact_sha256: str
    tools: tuple[str, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.artifact_sha256):
            raise ValueError("Invalid artifact digest")
        for field_name in ("protocol_versions", "extensions", "tools"):
            values = getattr(self, field_name)
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"{field_name} must be unique and sorted")


APPROVED_RELEASES: frozenset[ServerDescriptor] = frozenset()
REVOKED_DIGESTS: frozenset[str] = frozenset()


def approve_server(descriptor: ServerDescriptor) -> None:
    """Admit only an exact reviewed and non-revoked release."""
    if descriptor.artifact_sha256 in REVOKED_DIGESTS:
        raise PermissionError("Server release has been revoked")
    if descriptor not in APPROVED_RELEASES:
        raise PermissionError("Server release is not approved")


def require_descriptor_matches(
    manifest: PackageManifest,
    descriptor: ServerDescriptor,
) -> None:
    """Require registry identity fields to match verified manifest fields."""
    descriptor_identity = (
        descriptor.name,
        descriptor.version,
        descriptor.publisher,
        descriptor.key_id,
        descriptor.artifact_sha256,
    )
    manifest_identity = (
        manifest.name,
        manifest.version,
        manifest.publisher,
        manifest.key_id,
        manifest.artifact_sha256,
    )
    if descriptor_identity != manifest_identity:
        raise SecurityError("Registry descriptor does not match verified manifest")


def admit_release(
    manifest_bytes: bytes,
    signature: bytes,
    package_content: bytes,
    sbom_bytes: bytes,
    verifier: ServerVerifier,
    descriptor: ServerDescriptor,
    *,
    expected_name: str,
    expected_version: str,
    ci_gate_passed: bool,
) -> PackageManifest:
    """Compose CI, manifest, artifact, SBOM, and registry gates."""
    if ci_gate_passed is not True:
        raise SecurityError("Required CI policy did not pass")
    manifest = verify_package(
        manifest_bytes,
        signature,
        package_content,
        verifier,
        expected_name=expected_name,
        expected_version=expected_version,
    )
    verify_bound_sbom(manifest, sbom_bytes)
    require_descriptor_matches(manifest, descriptor)
    approve_server(descriptor)
    return manifest


@dataclass(frozen=True)
class DependencyStatus:
    name: str
    current_version: str
    candidate_version: str | None
    vulnerability_severity: str | None
    candidate_addresses_vulnerability: bool

    def __post_init__(self) -> None:
        valid = {None, "low", "medium", "high", "critical"}
        if self.vulnerability_severity not in valid:
            raise ValueError("Unknown vulnerability severity")
        if not isinstance(self.candidate_addresses_vulnerability, bool):
            raise ValueError("Remediation status must be a boolean")
        if self.candidate_version is None and self.candidate_addresses_vulnerability:
            raise ValueError("A remediation claim requires a candidate version")


def plan_maintenance(
    dependencies: tuple[DependencyStatus, ...],
) -> tuple[str, ...]:
    """Produce review actions without upgrading a package."""
    actions: list[str] = []
    for dependency in dependencies:
        urgent = dependency.vulnerability_severity in {"critical", "high"}
        candidate = dependency.candidate_version
        if urgent and (
            candidate is None or not dependency.candidate_addresses_vulnerability
        ):
            actions.append(
                f"CONTAIN {dependency.name}: no verified remediation candidate"
            )
        elif urgent:
            actions.append(
                f"TEST {dependency.name} {candidate}: verify provenance, "
                "compatibility, security behavior, staged rollout, and rollback"
            )
        elif dependency.vulnerability_severity is not None and candidate is None:
            actions.append(
                f"ASSESS {dependency.name}: vulnerability has no candidate"
            )
        elif candidate is not None:
            actions.append(
                f"REVIEW {dependency.name} {candidate}: schedule normal testing"
            )
    return tuple(actions)


@dataclass(frozen=True)
class PinnedDependency:
    name: str
    version: str
    sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?", self.name):
            raise ValueError("Pinned dependency name is invalid")
        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("Pinned dependency version is required")
        if not isinstance(self.sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ValueError("Pinned dependency digest must be SHA-256 hex")


def _canonical_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def verify_lockfile_integrity(
    locked: tuple[PinnedDependency, ...],
    installed: dict[str, tuple[str, bytes]],
) -> tuple[str, ...]:
    """Compare pinned archive bytes with a trusted installed inventory."""
    violations: list[str] = []
    expected: dict[str, PinnedDependency] = {}
    for dependency in locked:
        name = _canonical_package_name(dependency.name)
        if name in expected:
            violations.append(f"Duplicate lock entry: {name}")
        expected[name] = dependency

    actual: dict[str, tuple[str, bytes]] = {}
    for raw_name, package in installed.items():
        name = _canonical_package_name(raw_name)
        if name in actual:
            violations.append(f"Ambiguous installed package name: {name}")
        actual[name] = package

    for name in sorted(set(expected) - set(actual)):
        violations.append(f"Missing: {name}@{expected[name].version}")
    for name in sorted(set(actual) - set(expected)):
        violations.append(f"Unexpected: {name}@{actual[name][0]}")
    for name in sorted(set(expected) & set(actual)):
        dependency = expected[name]
        version, content = actual[name]
        if version != dependency.version:
            violations.append(
                f"Version mismatch: {name} expected {dependency.version}, got {version}"
            )
        measured = hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(measured, dependency.sha256):
            violations.append(f"Digest mismatch: {name}@{version}")
    return tuple(violations)


def _demo() -> None:
    package_content = b"tickets-server release 2.4.1"
    sbom_bytes = b'{"bomFormat":"CycloneDX","specVersion":"1.6"}'
    artifact_digest = hashlib.sha256(package_content).hexdigest()
    sbom_digest = hashlib.sha256(sbom_bytes).hexdigest()
    manifest_bytes = json.dumps(
        {
            "schema_version": "1",
            "name": "tickets-server",
            "version": "2.4.1",
            "publisher": "trusted-team",
            "key_id": "release-2026",
            "artifact_sha256": artifact_digest,
            "sbom_sha256": sbom_digest,
        },
        separators=(",", ":"),
    ).encode()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature = private_key.sign(
        manifest_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier = ServerVerifier({("trusted-team", "release-2026"): public_pem})
    descriptor = ServerDescriptor(
        name="tickets-server",
        publisher="trusted-team",
        key_id="release-2026",
        version="2.4.1",
        protocol_versions=("2026-07-28",),
        extensions=(),
        artifact_sha256=artifact_digest,
        tools=("create_ticket", "read_ticket"),
    )

    global APPROVED_RELEASES
    APPROVED_RELEASES = frozenset({descriptor})
    decision = evaluate_ci_gate((), scanner_completed=True)
    admitted = admit_release(
        manifest_bytes,
        signature,
        package_content,
        sbom_bytes,
        verifier,
        descriptor,
        expected_name="tickets-server",
        expected_version="2.4.1",
        ci_gate_passed=decision.allowed,
    )
    assert admitted.artifact_sha256 == artifact_digest

    try:
        admit_release(
            manifest_bytes,
            signature,
            package_content + b"tampered",
            sbom_bytes,
            verifier,
            descriptor,
            expected_name="tickets-server",
            expected_version="2.4.1",
            ci_gate_passed=True,
        )
    except SecurityError as exc:
        print(f"tampered release denied: {exc}")
    else:
        raise AssertionError("Tampered release should have been denied")

    print(f"release admitted: {admitted.name}@{admitted.version}")


if __name__ == "__main__":
    _demo()
