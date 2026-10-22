# Chapter 4 — Check issuer, audience, tenant and scope

Book coverage: the final chapter's Python token validator and the tenant,
resource-policy and tool-scope authorization gate.

`token_authorization.py` verifies an RS256 JWT with PyJWT, then requires an exact
tenant match, an application resource-policy decision, a registered tool and
that tool's exact scope. It exposes the chapter's `TokenClaims`, `TOOL_SCOPE`,
`validate_and_parse_token(raw_token, expected_aud)` and
`authorize_tool_call(claims, tool_name, args, subject_policy)` APIs.

From `code/`, using the shared Python environment and Python 3.12 or later:

```sh
python chapter04/token_authorization.py
python -m unittest discover -s tests -p test_early_python.py -v
```

The demo generates an ephemeral in-memory RSA key, signs and verifies a synthetic
JWT, authorizes a search and denies ticket creation without `tickets:write`.
Its injected key adapter makes no network requests. No key or token is printed,
saved, or used to access a real account.

## Configuration and dependency

This code needs the pinned `PyJWT[crypto]` dependency in the shared requirements;
it is not a standard-library-only example. Install that environment before
running it. RSA/RS256 is retained to match the chapter's configured JWT profile.

The chapter leaves `TRUSTED_ISSUER` and `TRUSTED_JWKS_URI` as deployment inputs.
This module avoids constructing a client with an empty URI at import. Instead,
call `configure_trusted_jwks(issuer, jwks_uri)` once at startup, after checking
the exact issuer and `jwks_uri` from trusted metadata against endpoint policy.
Do not guess a provider's JWKS path. The demo URI is an explicitly offline fixture
for the injected adapter, not a real provider endpoint.

The default PyJWT 2.15.1 adapter uses verified TLS, a five-second network timeout,
a 300-second JWKS-set cache, no indefinite per-key cache, and a 30-second unknown-key
refresh cooldown. These are illustrative bounded policy values, not a claim
about every provider's rollover schedule. Configure them to match the provider's
documented overlap and emergency-removal policy. The pinned adapter refuses
redirects. Apply gateway/network response-size, concurrency and wall-clock limits
as well; this helper is not a complete outbound-network security boundary.

## Corrections made while assembling the code

- `TokenClaims` validates claim types and bounded scope tuples. Untrusted tenant
  values are rejected instead of being coerced with `str()`.
- The issuer and JWKS resolver come from startup policy; the expected audience
  comes from resource-server configuration. None comes from model arguments.
- Unknown tools deny access. Scope strings require exact membership; a wildcard
  such as `admin:*` does not implicitly grant every operation.
- Failure omits token text and underlying exception details. The resource-policy
  callback must return the literal boolean `True`; failures deny the request.

## Trust boundary and limits

Construct `TokenClaims` through `validate_and_parse_token`; directly accepting
those fields from a request would bypass token validation. The verifier pins
RS256 and checks issuer, audience, signature, expiry and required identity claims.
It also applies PyJWT's normal checks to applicable optional time claims. A raw
audience array may be valid; the returned `aud` is the intended audience whose
membership was verified. The resource-policy callback must resolve the subject's
rights from trusted, tenant-scoped application data. Validate tool arguments
before policy evaluation and dispatch, and keep them stable across both steps.

Revocation events, refresh rotation, DPoP/mTLS proofs, token exchange and a live
authorization server are chapter architecture topics, not implemented features
of this compact gate. The example does not pretend to verify those controls.

Tests use freshly generated keys and a synthetic JWKS to check valid signatures,
wrong keys/algorithms, issuer/audience/expiry failures, unknown keys, tenant and
resource-policy denial, missing scopes, malformed claims and wildcard assumptions.
