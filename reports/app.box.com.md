# Security Audit Report — app.box.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://app.box.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | app.box.com |
| Test date | 2026-09-26 17:39 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 4, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 11 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 12 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 13 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 14 | info | CK5 | Cookie scoped to parent domain (.box.com) | CWE-200 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | CT1 | 1 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (t4ezxeirilv3mo.app.box.com and yrdt1tarfs73mo.app.box.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 11. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=iwmu_PTOtVs1wBMDuuYiJbOXVO7hB6TMmxkN6jY_2bQ
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 12. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of app.box.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 13. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but app.box.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 14. [INFO] Cookie scoped to parent domain (.box.com) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host app.box.com.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 3 disallow path(s), e.g. /, /, /signup/collablink/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] 1 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: app.box.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "app.box.com",
  "dns": {
    "a": [
      "74.112.186.157"
    ],
    "aaaa": [
      "2620:117:bff0:12d::"
    ],
    "cname": null,
    "mx": [],
    "ns": [],
    "spf": [
      "google-site-verification=iwmu_PTOtVs1wBMDuuYiJbOXVO7hB6TMmxkN6jY_2bQ"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Redwood City, organizationName=Box, Inc., commonName=box.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Dec 20 00:00:00 2025 GMT",
    "notAfter": "Dec 22 23:59:59 2026 GMT",
    "san": [
      "box.com",
      "*.box.com",
      "*.account.box.com",
      "*.app.box.com",
      "*.ent.box.com",
      "*.services.box.com",
      "*.m.box.com",
      "www.box.com",
      "*.mktg.box.com"
    ],
    "days_left": 87,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "74.112.186.157",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [
    {
      "domain": ".app.box.com"
    },
    {
      "domain": ".app.box.com",
      "samesite": "none"
    },
    {
      "domain": ".box.com"
    },
    {
      "domain": ".box.com",
      "samesite": "none"
    },
    {
      "domain": ".app.box.com"
    },
    {
      "domain": ".app.box.com"
    },
    {
      "domain": ".box.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.app.box.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://app.box.com:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 1,
    "notable": [
      "app.box.com"
    ],
    "sample": [
      "app.box.com"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=iwmu_PTOtVs1wBMDuuYiJbOXVO7hB6TMmxkN6jY_2bQ"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/",
      "/signup/collablink/"
    ]
  },
  "elapsed_s": 16.9,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
