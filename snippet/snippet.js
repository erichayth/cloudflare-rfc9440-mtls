/**
 * Cloudflare Snippet — RFC 9440 mTLS Client Certificate Forwarding
 *
 * Forwards a verified mTLS client certificate from Cloudflare's edge to
 * an origin server using the standard `Client-Cert` and `Client-Cert-Chain`
 * HTTP headers defined by RFC 9440.
 *
 * This is the Snippet variant of the companion Worker. Snippets are free
 * on every paid Cloudflare plan and have a tighter runtime than Workers
 * (no bindings, no outbound fetch except the implicit pass-through, no
 * console.log observability). If you need per-request structured logging,
 * use the Worker variant instead.
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
 * Defense-in-depth: strips ALL legacy "X-SSL-*" headers and the status
 * header on every request, regardless of EMIT flag state. An origin that
 * reads either the standard or legacy header shape cannot be tricked by
 * client-injected values.
 */

// Migration-window dual-emit. Default ON for the Snippet because it's
// commonly used for the "old origin can't yet read Client-Cert" case;
// flip to false once the origin is reading the standard header.
const EMIT_LEGACY = true;

// Optional CN-pattern extraction. Default OFF.
//
// When enabled, extracts a substring from the cert's Subject DN Common
// Name (CN) using the configured regex and forwards it as a dedicated
// header. The first capture group of the regex becomes the header value.
//
// Example use cases:
//   - Trailing 10-digit ID after a dot in CN:  /\.(\d{10})$/
//   - Leading employee ID prefix:              /^(E\d+)\s/
//   - Email-style CN:                          /^([^@]+)@/
const EMIT_CN_PATTERN = false;
const CN_PATTERN_HEADER_NAME = "X-Client-Subject-ID";
const CN_PATTERN_REGEX = /\.(\d{10})$/;

// Headers we may set — stripped on every inbound request regardless of
// EMIT flags so client-injected values can't leak through to the origin.
const HEADERS_WE_OWN = [
  "Client-Cert",
  "Client-Cert-Chain",
  "X-Client-Cert-Status",
  CN_PATTERN_HEADER_NAME,
  "X-SSL-Client-Verify",
  "X-SSL-Client-DN",
  "X-SSL-Client-Issuer",
  "X-SSL-Client-Serial",
  "X-SSL-Client-Fingerprint",
  "X-SSL-Client-NotBefore",
  "X-SSL-Client-NotAfter",
];

export default {
  async fetch(request) {
    const tls = request.cf?.tlsClientAuth;
    const headers = new Headers(request.headers);

    // Sanitize: always strip every header we may set.
    for (const h of HEADERS_WE_OWN) headers.delete(h);

    // Determine cert state. cert_revoked is a required check per Cloudflare
    // docs — a cert can be SUCCESS-verified at TLS handshake but revoked
    // by the time we forward (OCSP/CRL update timing).
    const certPresented = tls?.certPresented === "1";
    const certRevoked =
      tls?.certRevoked === "1" || tls?.certRevoked === true;
    const certVerifySucceeded = tls?.certVerified === "SUCCESS";

    if (!certPresented) {
      headers.set("X-Client-Cert-Status", "none");
    } else if (certRevoked) {
      headers.set("X-Client-Cert-Status", "revoked");
    } else if (!certVerifySucceeded) {
      headers.set(
        "X-Client-Cert-Status",
        `failed:${tls.certVerified || "unknown"}`,
      );
    } else {
      // Trusted — forward standard RFC 9440 headers
      if (tls.certRFC9440 && tls.certRFC9440TooLarge !== true) {
        headers.set("Client-Cert", tls.certRFC9440);
      }
      if (tls.certChainRFC9440 && tls.certChainRFC9440TooLarge !== true) {
        headers.set("Client-Cert-Chain", tls.certChainRFC9440);
      }

      const tooLarge = [];
      if (tls.certRFC9440TooLarge === true) tooLarge.push("leaf");
      if (tls.certChainRFC9440TooLarge === true) tooLarge.push("chain");
      headers.set(
        "X-Client-Cert-Status",
        tooLarge.length ? `too-large:${tooLarge.join(",")}` : "verified",
      );

      // Optional legacy dual-emit (flip EMIT_LEGACY to false once the
      // origin reads the standard Client-Cert header).
      if (EMIT_LEGACY) {
        headers.set("X-SSL-Client-Verify", "SUCCESS");
        if (tls.certSubjectDN)
          headers.set("X-SSL-Client-DN", tls.certSubjectDN);
        if (tls.certIssuerDN)
          headers.set("X-SSL-Client-Issuer", tls.certIssuerDN);
        if (tls.certSerial) headers.set("X-SSL-Client-Serial", tls.certSerial);
        if (tls.certFingerprintSHA1)
          headers.set("X-SSL-Client-Fingerprint", tls.certFingerprintSHA1);
        if (tls.certNotBefore)
          headers.set("X-SSL-Client-NotBefore", tls.certNotBefore);
        if (tls.certNotAfter)
          headers.set("X-SSL-Client-NotAfter", tls.certNotAfter);
      }

      // Optional CN-pattern extraction.
      if (EMIT_CN_PATTERN && tls.certSubjectDN) {
        const cn = tls.certSubjectDN.match(/CN=([^,/]+)/);
        if (cn) {
          const m = cn[1].match(CN_PATTERN_REGEX);
          if (m && m[1]) headers.set(CN_PATTERN_HEADER_NAME, m[1]);
        }
      }
    }

    return fetch(new Request(request, { headers }));
  },
};
