# RFC 9440 mTLS Client Certificate Forwarding Worker

A Cloudflare Worker that forwards a verified mTLS client certificate from Cloudflare's edge to an origin server using the standard [RFC 9440](https://www.rfc-editor.org/rfc/rfc9440) `Client-Cert` and `Client-Cert-Chain` HTTP headers.

Designed as a hardened, audit-ready reference implementation. Addresses every security consideration in the [Cloudflare documentation for client certificate forwarding](https://developers.cloudflare.com/ssl/client-certificates/forward-a-client-certificate/), plus several defense-in-depth additions.

## Why this exists

The Cloudflare docs offer three ways to forward a client cert to your origin:

1. **Transform Rules** (declarative, no code) — best for simple "set the header if cert is verified" scenarios
2. **Snippet** (~30 lines of JS, free) — best when you need slightly more logic than rules can express
3. **Worker** (this) — best when you need:
   - Per-request structured logging for audit trails
   - Dual-emit of legacy `X-SSL-*` headers alongside RFC 9440 standard headers during a migration window
   - Configurable extraction of an identifier from the Subject DN CN
   - Future hooks for outbound API calls (revocation lookup, audit ingest, etc.)

If you don't need any of those, prefer Transform Rules — fewer moving parts.

## What it does

On every request:

1. **Sanitizes** any client-injected `Client-Cert`, `Client-Cert-Chain`, status, legacy `X-SSL-*`, or CN-pattern headers — unconditionally, regardless of which optional emit flags are enabled.
2. **Inspects** the validated TLS state at the edge (`request.cf.tlsClientAuth`):
   - Was a client certificate presented?
   - Did Cloudflare's edge verify it against your configured BYO CA?
   - Has the certificate been revoked?
   - Is the encoded value within the documented size limits (10 KiB leaf, 16 KiB chain)?
3. **Sets** appropriate request headers based on the decision:
   - `Client-Cert: :base64DER:` and `Client-Cert-Chain: :base64DER:, :base64DER:` when the cert is verified, non-revoked, and within size limits
   - `X-Client-Cert-Status: verified | revoked | failed:<reason> | none | too-large:leaf,chain` always, so the origin can fail closed rather than guess from header absence
   - Optionally legacy `X-SSL-Client-*` headers for origins not yet migrated
   - Optionally a configurable identifier header extracted from the Subject DN CN
4. **Logs** one structured JSON line per request with the decision plus cert metadata. The raw cert bytes are never logged — only metadata (Subject DN, Issuer DN, serial, fingerprint, validity, the `*_too_large` flags, plus request context like CF-Ray and client IP).
5. **Forwards** the modified request to your origin.

## Security posture

Per the Cloudflare documentation's listed security considerations:

| Requirement | Handled |
|---|---|
| Strip client-injected `Client-Cert` / `Client-Cert-Chain` unconditionally | ✅ |
| Check `cert_verified` before trusting cert data | ✅ |
| Check `cert_revoked` before trusting cert data | ✅ |
| Honor 10 KiB leaf / 16 KiB chain size limits | ✅ |

Defense-in-depth (beyond the doc's requirements):

- **Strips legacy and status headers unconditionally**, regardless of EMIT flag state. An origin that reads `X-SSL-Client-Verify` for trust decisions cannot be tricked by client-injected values, even when the Worker's dual-emit mode is off.
- **Logs every decision** so verification failures, revoked-cert attempts, and oversize requests are auditable rather than silent.

## Configuration

All toggles are constants at the top of `worker.js` so they're greppable and reviewable in code review:

| Constant | Default | Purpose |
|---|---|---|
| `EMIT_LEGACY_NGINX_HEADERS` | `false` | When `true`, also emit `X-SSL-Client-Verify`, `X-SSL-Client-DN`, etc. for origins that haven't been migrated to read the standard `Client-Cert` header. Use during migration; turn off when the cutover is complete. |
| `EMIT_CN_PATTERN_HEADER` | `false` | When `true`, extract a substring from the Subject DN CN using `CN_PATTERN_REGEX` and forward it as `CN_PATTERN_HEADER_NAME`. |
| `CN_PATTERN_REGEX` | `/\.(\d{10})$/` | First capture group becomes the header value. Default extracts a trailing 10-digit ID after a dot. |
| `CN_PATTERN_HEADER_NAME` | `"X-Client-Subject-ID"` | Header name for the extracted CN value. |
| `STATUS_HEADER` | `"X-Client-Cert-Status"` | Status signal name. Set falsy to suppress and use header absence as the negative signal. |
| `ENABLE_LOGGING` | `true` | Set `false` to suppress per-request JSON log lines. |

## Deploy

### Pre-requisites

- A Cloudflare zone with mTLS enabled — see [Enable mTLS](https://developers.cloudflare.com/ssl/client-certificates/enable-mtls/)
- A BYO CA loaded against that zone so `request.cf.tlsClientAuth.certVerified === "SUCCESS"` for legitimate cards
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) installed

### Steps

```sh
# Edit wrangler.toml — set your route pattern and zone_name
$EDITOR wrangler.toml

# Deploy
wrangler deploy
```

### Verify

Hit the bound hostname with a verified mTLS client certificate. Expected:

- Origin sees `Client-Cert: :base64DER:` and `X-Client-Cert-Status: verified`
- `wrangler tail` (or Workers Logs UI) shows a JSON log line with `"decision": "verified"`

Without a cert (or with an invalid one), origin sees `X-Client-Cert-Status: none | failed:<reason> | revoked` and no `Client-Cert` header.

## Logging shape

One JSON line per request. Example:

```json
{
  "ts": "2026-05-06T15:30:00.000Z",
  "decision": "verified",
  "trusted": true,
  "method": "GET",
  "host": "app.example.com",
  "path": "/api/secure",
  "cf_ray": "9f78...-IAD",
  "client_ip": "203.0.113.10",
  "cert": {
    "presented": "1",
    "verified": "SUCCESS",
    "revoked": "0",
    "subject_dn": "CN=Example User,O=Example Org,C=US",
    "issuer_dn": "CN=Example Issuing CA,O=Example Org,C=US",
    "serial": "1234ABCD",
    "fingerprint_sha256": "8decc53b...",
    "not_before": "Jan 27 14:31:47 2025 GMT",
    "not_after": "Dec 13 13:50:07 2034 GMT",
    "rfc9440_too_large": false,
    "chain_too_large": false
  }
}
```

Read these via:

- `wrangler tail` for live debugging during testing
- Workers Logs UI for retrospective ad-hoc queries
- Logpush to R2 / S3 / Splunk / etc. for long-term retention and audit

## Testing

The [Cloudflare doc's example Transform Rules](https://developers.cloudflare.com/ssl/client-certificates/forward-a-client-certificate/) include three negative tests worth running against this Worker as well:

1. **Injection without a cert**: send a request with `-H "Client-Cert: :ATTACKER:"` but no actual client cert. Origin should see no `Client-Cert` header (the Worker stripped the inbound value, and the absence of a verified cert prevents setting a new one). `X-Client-Cert-Status: none`.

2. **Wrong CA**: present a self-signed or wrong-CA cert. Origin should see no `Client-Cert` header. `X-Client-Cert-Status: failed:<reason>`. The `wrangler tail` log line shows `"decision": "failed"`.

3. **Revoked cert**: present a previously-valid cert that's now in your CA's CRL. Origin should see no `Client-Cert` header. `X-Client-Cert-Status: revoked`. Log line shows `"decision": "revoked"`.

## Trust model

This Worker assumes the inbound TLS connection has been authenticated by Cloudflare's edge against your configured BYO CA. It does NOT verify cert signatures itself — `certVerified === "SUCCESS"` is the trust signal.

For the origin to safely trust the headers this Worker forwards, the origin must also be locked down to receive requests *only* from Cloudflare. Common approaches:

- **Cloudflare Authenticated Origin Pulls (AOP)** — Cloudflare presents a TLS client cert to your origin, origin requires it. Cryptographic, doesn't depend on IPs.
- **Cloudflare Tunnel** — origin has no public IP at all, only reachable via the tunnel daemon.
- **IP allowlist** — origin firewall accepts only Cloudflare's published egress IP ranges. Simplest but most fragile.

Without one of these in place, an attacker who finds the origin IP can bypass Cloudflare entirely and inject any header they like. **The cert-forwarding mechanism alone does not make the origin secure** — it only conveys identity to an origin that's already locked down.

## License

MIT
