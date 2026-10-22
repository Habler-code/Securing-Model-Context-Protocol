# Chapter 10 — Constrain application egress

`egress_firewall.py` follows the **Python** `EgressFirewall` class and `safe_fetch` method in the current Chapter 10 export, checked on 22 October 2026. It uses standard-library `urllib` instead of `requests` to keep the companion's HTTP dependency footprint small. It returns a bounded `EgressResponse` with `status_code`, `headers`, `content` and UTF-8 `text`; it does not return a full `requests.Response`.

From the repository's `code` directory in the documented Python virtual environment:

```sh
python chapter10/egress_firewall.py
python -m unittest discover -s tests -p test_middle_python.py -v
```

The demo injects an approved local response, then blocks a lookalike domain and a metadata destination. It makes **no network request**. To use the real transport, a trusted launcher constructs `EgressFirewall(approved_domains)`; normal tool arguments cannot select the transport adapter.

## Relation to the chapter

| Manuscript section | Companion implementation |
| --- | --- |
| Application-layer egress firewall | `EgressFirewall(allowed_domains)` and `safe_fetch(url, method="GET", **kwargs)` retain the chapter's names |
| Exact host and HTTPS checks | Validated hostname policy, complete HTTPS URL, exact hostname equality |
| Reject transparent redirects | A private no-redirect opener never follows 3xx responses; `safe_fetch` rejects them |
| Container baseline and isolation | `compose.illustrative.yaml` records a restrictive baseline; it is illustrative and was not deployed |

The companion adds URL length/credential/port checks, GET/POST-only requests, 64 KiB request and 1 MiB response ceilings, a fixed ten-second **socket operation** timeout, and a narrow runtime option allowlist. The only kwargs are `data` (bounded text/bytes) and `headers` (Accept/Content-Type). Caller-supplied redirects, timeouts, proxies, credentials, or TLS-verification overrides are rejected. Add service credentials only in a trusted adapter. TLS verification uses the system trust store, checks hostnames, and requires TLS 1.3. Ambient proxy environment variables are disabled; deployments requiring a gateway should provide an approved adapter explicitly.

## What the wrapper does not establish

Hostname checks do not pin DNS answers or constrain direct sockets. A required proxy/network boundary must check every resolved IPv4/IPv6 destination at connection time, prevent DNS rebinding, and deny private/link-local/metadata routes according to deployment policy. A compromised process can bypass any application wrapper.

The urllib timeout applies to blocking socket operations. It is **not a complete wall-clock deadline** for DNS and slow streaming. Gateways and isolated workers must enforce total deadlines, concurrent-call limits, byte/rate budgets and cancellation. The fixture tests verify wrapper policy, not deployed DNS, gateway or sandbox behavior.

The Compose file requires `APPROVED_DOCUMENT_IMAGE`. Supply a verified digest-pinned image and approved input directory, apply maintained seccomp/MAC policies, confirm runtime selection, and perform isolated negative tests for mounts, resources and egress. The Compose baseline is supporting configuration, not a deployed Docker, gVisor, Firecracker or WebAssembly lab.

Tests cover allowed hosts, malformed policy, lookalike/private URLs, scheme/port/userinfo rejection, method/option/header restrictions, byte ceilings, redirects and the fixed timeout argument. No credentials or certificates are embedded.

Primary references: [Python urllib.request](https://docs.python.org/3/library/urllib.request.html), [Python SSL defaults](https://docs.python.org/3/library/ssl.html#ssl.create_default_context), [Docker security](https://docs.docker.com/engine/security/), and [gVisor security model](https://gvisor.dev/docs/architecture_guide/security/).
