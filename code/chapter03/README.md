# Chapter 3 — Generate PKCE and validate a token exchange

Book section: “Implementation (Python): PKCE, state, issuer validation, and token
exchange.”

`oauth_pkce.py` assembles the chapter's OAuth helpers.
It uses only Python 3.11's standard library. It generates PKCE and state, builds
an authorization URL, checks callback state and issuer, and exchanges a code
only at the exact trusted token endpoint. No MCP SDK is required.

From `code/`:

```sh
python chapter03/oauth_pkce.py
python -m unittest discover -s tests -p test_early_python.py -v
```

The demo makes no network requests. It shows a valid synthetic callback and a
rejected state mismatch. The tests inject local token responses and failures;
they need no identity provider account or real credential.

The chapter also lists an Authorization Server, browser and HTTP client for
practicing a real consent flow. They are not needed by these offline helpers or
tests. The companion does not deploy Keycloak or claim to provide a complete
interactive authorization application.

## Python flow and deployment boundaries

The static `TRUSTED_OAUTH_PROFILE` fixes issuer
`https://auth.example.com`, authorization endpoint `/authorize`, token endpoint
`/oauth/token`, and resource `https://mcp.example.com`. It replaces safely
validated metadata for this teaching profile; it is not dynamic discovery.
`require_trusted_endpoint` checks exact profile membership before accepting the
HTTPS URL. The token opener validates TLS certificates and refuses redirects.
The exchange has a 10-second I/O timeout and a 1 MiB response cap; malformed
JSON, missing tokens and non-bearer token types fail with a generic error.

Client identifier, redirect URI and requested scopes must come from protected
registered-client configuration. They are not model-generated request fields.
The returned flow contains the secret verifier and must be kept out of logs,
model context and browser-visible state. The demo does not print it.

`validate_callback` deliberately requires the authorization response's exact
`iss` value in this educational profile. An actual deployment must confirm the
provider supports and advertises that response-issuer contract. A callback
adapter must reject duplicate `state`, `iss`, `code` and `error` parameters
before selecting a value; it must reject error responses instead of exchanging
them. Do not flatten a multivalue query into a dictionary and silently choose
one of several conflicting security parameters.

These pure helpers do not implement pending-login storage. A production adapter
must persist state, verifier, issuer, client, redirect URI, initiating session
and expiry in a protected pending-flow record; bind callbacks to that session;
and atomically consume the matching record once. A successful call to
`validate_callback` alone does not prevent replay. Enforce the pending flow's
expiry and one-time consumption before exchanging the code, including concurrent
callbacks. In a multiprocess deployment this needs a transactional shared store,
not a process-local dictionary. A retry after a failed exchange starts a new flow.

The `urllib` timeout bounds individual blocking I/O; an edge/server wall-clock
deadline and concurrency limits are still required against a slow peer.
Token storage, refresh, revocation, OIDC ID-token/nonce validation and resource
server token verification remain explicit integration work. This module is not
a complete OAuth browser application or MCP runtime.

The assembled module retains the book's public helper names and profile. Its
additional local checks bound input fields, reject malformed PKCE values, and
confirm the stored challenge matches the verifier. It suppresses underlying
errors and uses a redirect error without a URL to avoid diagnostic leaks. The
token parser requires UTF-8 JSON. These checks complete the teaching module;
they do not add browser routing or pending-flow storage.
