# Chapter 5 — Normalize verified provider claims

Book section: “Implementation: Normalizing IdP claims in Python.”

`principal_mapping.py` assembles the chapter's claim-mapping example.
It exposes the same frozen `Principal`, `ProviderClaimProfile` and
`VerifiedMembership` records, plus `required_string_claim` and `normalize_claims`.
It requires Python 3.12 or later and only the standard library.

From `code/`:

```sh
python chapter05/principal_mapping.py
python -m unittest discover -s tests -p test_early_python.py -v
```

The demo uses a synthetic issuer and verified application membership. A provider
claim requesting `admin` does not override the membership's `reader` role. A
different subject is rejected. No provider account or SDK is required.

## Current chapter's identity contract

The upstream sign-in component must first verify signature, issuer, audience,
token purpose and expiry, then establish the verified issuer/subject pair.
An application-owned account-linking and membership adapter supplies the
`VerifiedMembership` record. Neither input may come directly from a model or an
unverified token. Missing membership stops onboarding; email or email-domain
verification never substitutes for a membership binding.

Profiles are protected configuration keyed by exact issuer. `tenant_claim` and
`user_claim` name top-level strings that must match the membership identifiers;
`None` disables that alias comparison. The adapter never guesses another alias
as a fallback. For example, verified Entra `tid`/`oid` can be selected only when
the application stores those same provider identifiers. A membership-only
profile is appropriate when local application IDs use another namespace. Stytch
organization/member aliases require an explicitly approved upstream mapping;
the example does not assume every Stytch token emits top-level fields.

Application roles always come from `VerifiedMembership`, never from provider
roles or a token. Unused additional provider claims do not change the result.
The assembled helper adds bounded string, control-character and role-count
checks to the book's nonempty-string checks. It still does not validate tokens,
issue MCP access tokens or operate an account-linking store.

Tests cover membership-only and selected-alias profiles, unused claims,
membership mismatch, missing/wrong claim types, unknown issuers and role source.
