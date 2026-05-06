/**
 * Cloudflare Worker — RFC 9440 mTLS Client Certificate Forwarding
 *
 * Forwards a verified mTLS client certificate from Cloudflare's edge to
 * an origin server using the standard `Client-Cert` and `Client-Cert-Chain`
 * HTTP headers defined by RFC 9440.
 *
 * Security: addresses every consideration listed in the Cloudflare docs at
 * https://developers.cloudflare.com/ssl/client-certificates/forward-a-client-certificate/
 *
 *   1. Strips client-injected Client-Cert / Client-Cert-Chain on every
 *      request (RFC 9440 §4 — required to prevent header injection).
 *   2. Checks cert_verified before trusting cert data.
 *   3. Checks cert_revoked before trusting cert data.
 *   4. Honors the documented size limits (10 KiB leaf / 16 KiB chain) via
 *      the *TooLarge runtime flags.
 *
 * Defense-in-depth (beyond the doc's requirements):
 *
 *   - Strips ALL legacy "X-SSL-*" headers, the status header, and any
 *     optional CN-extraction headers on every request, regardless of
 *     EMIT flags. An origin that reads either the standard or legacy
 *     header shape cannot be tricked by client-injected values, even
 *     when this Worker isn't actively setting those headers.
 *
 *   - Emits one structured JSON log line per request (decision +
 *     cert metadata only — never the cert bytes themselves) so cert
 *     verification failures, revoked-cert attempts, and oversize
 *     requests are auditable rather than silent. Read via
 *     `wrangler tail`, the Workers Logs UI, or Logpush.
 *
 * References:
 *   - RFC 9440  https://www.rfc-editor.org/rfc/rfc9440
 *   - Cloudflare docs:
 *     https://developers.cloudflare.com/ssl/client-certificates/forward-a-client-certificate/
 */

// ─────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────

// Migration-window dual-emit. Default OFF.
//
// When `true`, the Worker also emits a set of legacy Nginx-style headers
// (X-SSL-Client-Verify, X-SSL-Client-DN, etc.) alongside the standard
// RFC 9440 Client-Cert header. Use this only if an origin app cannot yet
// be updated to read the standard `Client-Cert` header. Flip back to false
// once the migration completes.
const EMIT_LEGACY_NGINX_HEADERS = false;

// Optional CN-pattern extraction. Default OFF.
//
// When configured, the Worker extracts a substring from the cert's Subject
// DN Common Name (CN) using a configurable regex and forwards it as a
// dedicated header. Useful for origins that want a pre-parsed identifier
// (employee ID, badge number, etc.) without having to crack the cert
// themselves.
//
// Set EMIT_CN_PATTERN_HEADER = true and adjust CN_PATTERN_REGEX /
// CN_PATTERN_HEADER_NAME for your environment. The first capture group
// of the regex becomes the header value. If the regex doesn't match,
// no header is set.
//
// Example use cases:
//   - Trailing 10-digit ID after a dot in CN (e.g. CN=LAST.FIRST.M.1234567890)
//       CN_PATTERN_REGEX = /\.(\d{10})$/
//   - Leading employee ID prefix (e.g. CN=E12345 Smith, John)
//       CN_PATTERN_REGEX = /^(E\d+)\s/
//   - Email-style subject CN (e.g. CN=user@example.com)
//       CN_PATTERN_REGEX = /^([^@]+)@/
const EMIT_CN_PATTERN_HEADER = false;
const CN_PATTERN_HEADER_NAME = "X-Client-Subject-ID";
const CN_PATTERN_REGEX = /\.(\d{10})$/;

// Status header name. Set to a falsy value to suppress entirely if you'd
// rather rely on header absence as the negative signal.
const STATUS_HEADER = "X-Client-Cert-Status";

// Structured per-request logging. Default ON; cheap (one JSON.stringify
// + console.log per request). Set to false to silence.
const ENABLE_LOGGING = true;

// All headers we may set. Stripped from every inbound request unconditionally
// so client-injected values can never reach the origin, regardless of which
// EMIT_* flags are toggled.
const HEADERS_WE_OWN = Object.freeze([
  "X-SSL-Client-Verify",
  "X-SSL-Client-DN",
  "X-SSL-Client-Issuer",
  "X-SSL-Client-DN-Legacy",
  "X-SSL-Client-Issuer-Legacy",
  "X-SSL-Client-Serial",
  "X-SSL-Client-Issuer-Serial",
  "X-SSL-Client-Fingerprint",
  "X-SSL-Client-NotBefore",
  "X-SSL-Client-NotAfter",
  CN_PATTERN_HEADER_NAME,
]);

// ─────────────────────────────────────────────────────────────────────────
// Worker entry point
// ─────────────────────────────────────────────────────────────────────────

export default {
  /**
   * @param {Request} request
   * @param {Record<string, unknown>} _env
   * @param {ExecutionContext} _ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, _env, _ctx) {
    const tls = request.cf?.tlsClientAuth;
    const headers = new Headers(request.headers);

    // ── Step 1: Sanitize. Strip every header we may set, on every request,
    // regardless of EMIT_* flags. RFC 9440 §4 + Cloudflare docs require
    // unconditional sanitization of Client-Cert / Client-Cert-Chain. We
    // extend the same hygiene to legacy + status + CN-pattern headers
    // because origins that trust those headers are equally vulnerable
    // to injection.
    headers.delete("Client-Cert");
    headers.delete("Client-Cert-Chain");
    if (STATUS_HEADER) headers.delete(STATUS_HEADER);
    for (const h of HEADERS_WE_OWN) headers.delete(h);

    // ── Step 2: Determine cert state. Both certVerified AND certRevoked
    // are required checks per Cloudflare's documented security model — a
    // cert can be SUCCESS-verified at TLS handshake but revoked between
    // handshake and header forwarding (OCSP/CRL update timing).
    const certPresented = tls?.certPresented === "1";
    const certRevoked =
      tls?.certRevoked === "1" || tls?.certRevoked === true;
    const certVerifySucceeded = tls?.certVerified === "SUCCESS";
    const certTrusted =
      certPresented && certVerifySucceeded && !certRevoked;

    // ── Step 3: Set headers based on cert state.
    let decision; // for logging

    if (!certPresented) {
      decision = "no-cert";
      if (STATUS_HEADER) headers.set(STATUS_HEADER, "none");
    } else if (certRevoked) {
      decision = "revoked";
      if (STATUS_HEADER) headers.set(STATUS_HEADER, "revoked");
    } else if (!certVerifySucceeded) {
      decision = "failed";
      if (STATUS_HEADER) {
        headers.set(
          STATUS_HEADER,
          `failed:${tls.certVerified || "unknown"}`,
        );
      }
    } else {
      // Cert is trusted. Forward in standard RFC 9440 format.
      const tooLarge = [];
      if (tls.certRFC9440TooLarge === true) tooLarge.push("leaf");
      if (tls.certChainRFC9440TooLarge === true) tooLarge.push("chain");

      if (tls.certRFC9440 && tls.certRFC9440TooLarge !== true) {
        headers.set("Client-Cert", tls.certRFC9440);
      }
      if (tls.certChainRFC9440 && tls.certChainRFC9440TooLarge !== true) {
        headers.set("Client-Cert-Chain", tls.certChainRFC9440);
      }

      if (tooLarge.length) {
        decision = `too-large:${tooLarge.join(",")}`;
        if (STATUS_HEADER) headers.set(STATUS_HEADER, decision);
      } else {
        decision = "verified";
        if (STATUS_HEADER) headers.set(STATUS_HEADER, "verified");
      }

      // Optional dual-emit for migration windows.
      if (EMIT_LEGACY_NGINX_HEADERS) {
        headers.set("X-SSL-Client-Verify", "SUCCESS");
        setIfPresent(headers, "X-SSL-Client-DN", tls.certSubjectDN);
        setIfPresent(headers, "X-SSL-Client-Issuer", tls.certIssuerDN);
        setIfPresent(
          headers,
          "X-SSL-Client-DN-Legacy",
          tls.certSubjectDNLegacy,
        );
        setIfPresent(
          headers,
          "X-SSL-Client-Issuer-Legacy",
          tls.certIssuerDNLegacy,
        );
        setIfPresent(headers, "X-SSL-Client-Serial", tls.certSerial);
        setIfPresent(
          headers,
          "X-SSL-Client-Issuer-Serial",
          tls.certIssuerSerial,
        );
        setIfPresent(
          headers,
          "X-SSL-Client-Fingerprint",
          tls.certFingerprintSHA1,
        );
        setIfPresent(headers, "X-SSL-Client-NotBefore", tls.certNotBefore);
        setIfPresent(headers, "X-SSL-Client-NotAfter", tls.certNotAfter);
      }

      // Optional CN-pattern extraction.
      if (EMIT_CN_PATTERN_HEADER) {
        const value = extractFromCN(tls.certSubjectDN, CN_PATTERN_REGEX);
        if (value) headers.set(CN_PATTERN_HEADER_NAME, value);
      }
    }

    // ── Step 4: Observability. Single structured log line per request.
    if (ENABLE_LOGGING) {
      logDecision(request, tls, decision, certTrusted);
    }

    // ── Step 5: Forward to origin.
    return fetch(new Request(request, { headers }));
  },
};

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

/**
 * Set a header only if the value is truthy. Avoids emitting empty headers,
 * which can confuse downstream parsers.
 *
 * @param {Headers} headers
 * @param {string} name
 * @param {string | undefined | null} value
 */
function setIfPresent(headers, name, value) {
  if (value) headers.set(name, value);
}

/**
 * Extract a captured group from the Subject DN's CN attribute using the
 * configured regex. Returns null if no CN is present, the regex doesn't
 * match, or the regex has no capture group.
 *
 * @param {string | undefined} subjectDN
 * @param {RegExp} pattern
 * @returns {string | null}
 */
function extractFromCN(subjectDN, pattern) {
  if (!subjectDN) return null;
  // Find the CN attribute. RFC 4514 separators are commas; some legacy
  // formats use slashes — accept both.
  const cnMatch = subjectDN.match(/CN=([^,/]+)/);
  if (!cnMatch) return null;
  const m = cnMatch[1].match(pattern);
  return m && m[1] ? m[1] : null;
}

/**
 * Emit one structured JSON log line per request. Captures the decision
 * plus cert metadata useful for audit (Subject DN, Issuer DN, serial,
 * fingerprint). Deliberately excludes the raw cert bytes — those go into
 * the Client-Cert header for the origin, not into logs.
 *
 * @param {Request} request
 * @param {object | undefined} tls
 * @param {string} decision
 * @param {boolean} certTrusted
 */
function logDecision(request, tls, decision, certTrusted) {
  const url = new URL(request.url);
  const log = {
    ts: new Date().toISOString(),
    decision,
    trusted: certTrusted,
    method: request.method,
    host: url.hostname,
    path: url.pathname,
    cf_ray: request.headers.get("cf-ray") || null,
    client_ip: request.headers.get("cf-connecting-ip") || null,
    cert: tls
      ? {
          presented: tls.certPresented,
          verified: tls.certVerified,
          revoked: tls.certRevoked,
          subject_dn: tls.certSubjectDN || null,
          issuer_dn: tls.certIssuerDN || null,
          serial: tls.certSerial || null,
          fingerprint_sha256: tls.certFingerprintSHA256 || null,
          not_before: tls.certNotBefore || null,
          not_after: tls.certNotAfter || null,
          rfc9440_too_large: tls.certRFC9440TooLarge === true,
          chain_too_large: tls.certChainRFC9440TooLarge === true,
        }
      : null,
  };
  console.log(JSON.stringify(log));
}
