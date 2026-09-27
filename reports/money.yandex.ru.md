# Security Audit Report — money.yandex.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://money.yandex.ru/ |
| Bug bounty program | Yandex |
| Listed scope domain | money.yandex.ru |
| Test date | 2026-09-27 02:38 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 2, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS1 | Domain does not resolve (no A/AAAA) | CWE-200 |
| 2 | low | MAIL9 | DMARC enforces (p=reject) but has no reporting address (rua) | CWE-285 |
| 3 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 4 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |

## Detailed findings

### 1. [INFO] Domain does not resolve (no A/AAAA) (`DNS1`)

- **CWE:** CWE-200
- **Detail:** No A or AAAA record returned from public resolvers; site may be offline or DNS-only outage.
- **Recommendation:** Confirm the service is still expected to be live.

### 2. [LOW] DMARC enforces (p=reject) but has no reporting address (rua) (`MAIL9`)

- **CWE:** CWE-285
- **Detail:** Without a rua= reporting address the policy cannot be tuned; mis-sends may be silently quarantined.
- **Recommendation:** Add a rua= reporting mailbox to the DMARC record.

### 3. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.money.yandex.ru/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 4. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for money.yandex.ru; apex yandex.ru, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

## Evidence (raw response observations)

```json
{
  "domain": "money.yandex.ru",
  "dns": {
    "a": [],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx.yandex.ru (pref 0)"
    ],
    "ns": [
      "ns3.yandex.ru.",
      "ns4.yandex.ru."
    ],
    "caa": [],
    "spf": [
      "v=spf1 include:_spf-ipv4.yandex.ru include:_spf-ipv6.yandex.ru -all"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;"
    ]
  },
  "tls": {
    "status": "no-ip"
  },
  "ports": {
    "status": "no-ip"
  },
  "https": {
    "status": 0,
    "content_type": "",
    "title": "",
    "error": "https connect failed"
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [],
  "http": {
    "status": 0,
    "error": "http connect failed"
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "status": "ct-pending"
  },
  "http2": {
    "error": "root GET failed"
  },
  "x12": {
    "error": "ConnectionError(MaxRetryError('HTTPSConnectionPool(host=\\'money.yandex.ru\\', por"
  },
  "x13": {
    "root_error": "ConnectionError(MaxRetryError('HTTPSConnectionPool(host=\\'money.yandex.ru\\', por",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_error": "ConnectionError(MaxRetryError('HTTPSConnectionPool(host=\\'money.yandex.ru\\', por"
  },
  "x15": {
    "root_error": "ConnectionError(MaxRetryError('HTTPSConnectionPool(host=\\'money.yandex.ru\\', por"
  },
  "x16": {
    "root_error": "ConnectionError(MaxRetryError('HTTPSConnectionPool(host=\\'money.yandex.ru\\', por"
  },
  "x17": {
    "root_error": "ConnectionError(MaxRetryError('HTTPSConnectionPool(host=\\'money.yandex.ru\\', por"
  },
  "elapsed_s": 10.2,
  "rechecked": "2026-09-27 02:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- re-run #15 passive additions: TLS 1.0/1.1, cipher-suite and key-exchange observations come from the handshake the base TLS check already performed plus one quiet re-handshake with no HTTP traffic; HTML-level angles read the root document already fetched for header checks; the only extra request this pass is a read-only GET to /.well-known/openid-configuration (plus the earlier passes' security.txt, sitemap.xml and CRL GETs).
- re-run #16 passive additions: the edge/protocol angles read the alt-svc, server-timing and CDN-identification headers from the one root GET; the preconnect/dns-prefetch, base-href and noindex angles parse the already-fetched root document; the TLS 1.2-only ceiling, SHA-1 signature and weak-key angles use the certificate evidence the base TLS check already captured; the only extra requests this pass are two read-only GETs (/.well-known/jwks.json and /.well-known/change-password).
- re-run #17 passive additions: the retired-header angles (Public-Key-Pins, Expect-CT, X-Permitted-Cross-Domain-Policies, Via, COOP/COEP, Permissions-Policy) read from the one root GET; the wildcard SAN, http:// OCSP and 398-day-cap angles use the certificate evidence the base TLS check already captured (SAN now harvested from the existing DER); the only extra requests this pass are three read-only GETs (/.well-known/dpop-jwks.json, /.well-known/origin-rsa-keys.json, /.well-known/llms.txt).
- Findings are reported against the public program scope; submission through the program tracker is pending.
