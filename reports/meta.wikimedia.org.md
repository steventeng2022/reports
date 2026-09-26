# Security Audit Report — meta.wikimedia.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://meta.wikimedia.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | meta.wikimedia.org |
| Test date | 2026-09-26 17:49 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 2, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 10 | info | CK5 | Cookie scoped to parent domain (.wikimedia.org) | CWE-200 |
| 11 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: mw-web.eqiad.main-5fb6d6bf94-p68ls
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: mw-web.eqiad.main-5fb6d6bf94-p68ls
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of meta.wikimedia.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 10. [INFO] Cookie scoped to parent domain (.wikimedia.org) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host meta.wikimedia.org.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 11. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 284 disallow path(s), e.g. /, /, User-agent:, #, /
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "meta.wikimedia.org",
  "dns": {
    "a": [
      "103.102.166.224"
    ],
    "aaaa": [
      "2001:df2:e500:ed1a::1"
    ],
    "cname": "dyna.wikimedia.org.",
    "mx": [],
    "ns": [],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.wikipedia.org",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Aug  5 19:15:41 2026 GMT",
    "notAfter": "Nov  3 19:15:40 2026 GMT",
    "san": [
      "*.m.mediawiki.org",
      "*.m.wikibooks.org",
      "*.m.wikidata.org",
      "*.m.wikimedia.org",
      "*.m.wikinews.org",
      "*.m.wikipedia.org",
      "*.m.wikiquote.org",
      "*.m.wikisource.org",
      "*.m.wikiversity.org",
      "*.m.wikivoyage.org",
      "*.m.wiktionary.org",
      "*.mediawiki.org",
      "*.planet.wikimedia.org",
      "*.wikibooks.org",
      "*.wikidata.org",
      "*.wikifunctions.org",
      "*.wikimedia.org",
      "*.wikimediafoundation.org",
      "*.wikinews.org",
      "*.wikipedia.org",
      "*.wikiquote.org",
      "*.wikisource.org",
      "*.wikiversity.org",
      "*.wikivoyage.org",
      "*.wiktionary.org",
      "*.wmfusercontent.org",
      "mediawiki.org",
      "w.wiki",
      "wikibooks.org",
      "wikidata.org",
      "wikifunctions.org",
      "wikimedia.org",
      "wikimediafoundation.org",
      "wikinews.org",
      "wikipedia.org",
      "wikiquote.org",
      "wikisource.org",
      "wikiversity.org",
      "wikivoyage.org",
      "wiktionary.org",
      "wmfusercontent.org"
    ],
    "days_left": 38,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "103.102.166.224",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: mw-web.eqiad.main-5fb6d6bf94-p68ls"
  ],
  "cookies": [
    {},
    {
      "domain": ".wikimedia.org"
    },
    {
      "samesite": "none"
    },
    {
      "domain": "meta.wikimedia.org",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.meta.wikimedia.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://meta.wikimedia.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 403,
    "/api/": 200
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 0,
    "notable": [],
    "sample": []
  },
  "cname_chain": [
    "dyna.wikimedia.org"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/",
      "/",
      "User-agent:",
      "#",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/"
    ]
  },
  "elapsed_s": 13.7,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
