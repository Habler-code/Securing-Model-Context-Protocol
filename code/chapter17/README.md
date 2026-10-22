# Chapter 17 — Securing the MCP supply chain

`supply_chain_security.py` verifies original signed manifest bytes with RSA-PSS
and SHA-256, binds artifact and SBOM digests, checks exact registry approval,
evaluates normalized scanner findings, plans maintenance, and detects lockfile
drift. Demonstration keys are generated at runtime and never saved.

The companion was compared with the chapter manuscript on
22 October 2026. The manifest, package/SBOM, CI gate, registry, maintenance, and
lockfile names and schemas match the executable chapter listings. `admit_release`
and `require_descriptor_matches` turn the chapter's explicitly labeled
admission pseudocode into a complete offline composition. They do not supply
deployment attestation, provenance appraisal, or a real registry adapter.
The companion additionally bounds manifest/signature inputs and rejects weak
trust-store keys and malformed metadata before admission.

Run from `code/` with Python 3.11 or later and the pinned dependency installed:

```bash
python -m pip install -r requirements.txt
python chapter17/supply_chain_security.py
python -m unittest discover -s tests -p test_late_regressions.py -v
```

Expected output includes `tampered release denied` and
`release admitted: tickets-server@2.4.1`.

The manifest parser rejects duplicate keys, unknown schema fields, invalid
digests, and input above 64 KiB. Trust-store loading accepts RSA keys of at least
2048 bits. Publisher/key IDs only select a locally trusted key; an identifier in
unverified metadata cannot introduce a new trust root. The verifier measures the
same artifact and SBOM bytes covered by the signature.

The teaching envelope is not an implementation of DSSE, Sigstore, SLSA, a
certificate transparency log, or remote attestation. A matching SBOM digest
proves byte binding, not SBOM completeness or vulnerability freedom. Production
integrations should verify the approved ecosystem envelope, publisher identity,
provenance, key revocation/rotation, and runtime deployment policy.

`APPROVED_RELEASES` and `REVOKED_DIGESTS` are trusted local fixture state. Scanner
results and completion flags must be produced by the controlled build pipeline,
not package authors. `verify_lockfile_integrity` expects a trusted inventory of
the exact archive bytes measured by the lock; it is not a native pip lockfile
parser or a reproducible hash of arbitrary extracted directories.

Tests exercise signature/artifact/SBOM tampering, release identity, weak keys,
manifest bounds, malformed maintenance metadata, scanner failures/severity, and
lockfile name normalization, duplicates, missing/extra packages, versions, and
digests. Nothing in the example downloads or installs a package automatically.
