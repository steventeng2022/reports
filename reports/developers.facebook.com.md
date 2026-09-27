# Security Audit Report — developers.facebook.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://developers.facebook.com/ |
| Bug bounty program | Facebook |
| Listed scope domain | developers.facebook.com |
| Test date | 2026-09-27 02:25 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 3, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 8 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 9 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 10 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 11 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 12 | info | HTML14 | Public root document marked noindex | CWE-200 |
| 13 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 14 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 15 | info | H13 | Cross-origin isolation only partially configured | CWE-693 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 7 days (notAfter Oct  4 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=15552000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 7. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 8. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 9. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of developers.facebook.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 10. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 57.144.92.141 carries PTR edge-star-shv-01-tpe5.facebook.com. for developers.facebook.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 11. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of developers.facebook.com sends a CSP but contains 1 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 12. [INFO] Public root document marked noindex (`HTML14`)

- **CWE:** CWE-200
- **Detail:** The root document of developers.facebook.com is marked noindex (meta robots or X-Robots-Tag); a public homepage that is not indexable is a posture anomaly worth reviewing.
- **Recommendation:** Confirm the noindex directive is intentional.

### 13. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of developers.facebook.com contains wildcard SAN entry(ies) *.facebook.com, *.facebook.net, *.fbcdn.net; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 14. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of developers.facebook.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 15. [INFO] Cross-origin isolation only partially configured (`H13`)

- **CWE:** CWE-693
- **Detail:** The root of developers.facebook.com sends COOP without COEP (same-origin-allow-popups); effective cross-origin isolation requires both COOP and COEP.
- **Recommendation:** Add the missing header (or remove the partial configuration).

## Evidence (raw response observations)

```json
{
  "domain": "developers.facebook.com",
  "dns": {
    "a": [
      "57.144.92.141"
    ],
    "aaaa": [
      "2a03:2880:f325:8d:face:b00c:0:2"
    ],
    "cname": "developers.c10r.facebook.com.",
    "mx": [
      "smtpin.vvv.facebook.com (pref 10)"
    ],
    "ns": [],
    "caa": [],
    "spf": [
      "v=spf1 include:facebookmail.com -all"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:a@dmarc.facebookmail.com; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_CHACHA20_POLY1305_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Menlo Park, organizationName=Meta Platforms, Inc., commonName=*.facebook.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jul  6 00:00:00 2026 GMT",
    "notAfter": "Oct  4 23:59:59 2026 GMT",
    "san": [
      "*.facebook.com",
      "*.facebook.net",
      "*.fbcdn.net",
      "*.fbsbx.com",
      "*.m.facebook.com",
      "*.messenger.com",
      "*.xx.fbcdn.net",
      "*.xy.fbcdn.net",
      "*.xz.fbcdn.net",
      "facebook.com",
      "messenger.com"
    ],
    "days_left": 7,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "57.144.92.141",
    "open": []
  },
  "https": {
    "status": 400,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.developers.facebook.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://developers.facebook.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 400,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 0,
    "notable": [],
    "sample": []
  },
  "cname_chain": [
    "developers.c10r.facebook.com"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 3023586267401638298209695178880455818,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "san": [
        "*.facebook.com",
        "*.facebook.net",
        "*.fbcdn.net",
        "*.fbsbx.com",
        "*.m.facebook.com",
        "*.messenger.com",
        "*.xx.fbcdn.net",
        "*.xy.fbcdn.net",
        "*.xz.fbcdn.net",
        "facebook.com",
        "messenger.com"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311330110603550407130a4d656e6c6f205061726b311d301b060355040a13144d65746120506c6174666f726d732c20496e632e3117301506035504030c0e2a2e66616365626f6f6b2e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260706000000",
      "not_after": "20261004235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "hsts_preloaded": true
  },
  "x12": {
    "status": 400,
    "ptr": [
      "edge-star-shv-01-tpe5.facebook.com."
    ]
  },
  "x13": {
    "root_status": 400,
    "http_status": 301,
    "p404_status": 404,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 400,
    "hsts": "max-age=15552000; preload",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_CHACHA20_POLY1305_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 400
  },
  "x16": {
    "root_status": 400,
    "noindex": true
  },
  "x17": {
    "wildcard_san": [
      "*.facebook.com",
      "*.facebook.net",
      "*.fbcdn.net",
      "*.fbsbx.com",
      "*.m.facebook.com"
    ],
    "ocsp_http": "http://ocsp.digicert.com",
    "isolation_partial": "COOP without COEP"
  },
  "elapsed_s": 21.6,
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
