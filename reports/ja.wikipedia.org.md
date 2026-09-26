# Security Audit Report — ja.wikipedia.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ja.wikipedia.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ja.wikipedia.org |
| Test date | 2026-09-26 14:53 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 2, Info: 6)

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

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: mw-web.eqiad.main-5fb6d6bf94-qbc7c
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
- **Detail:** Header reveals: mw-web.eqiad.main-5fb6d6bf94-qbc7c
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

## Evidence (raw response observations)

```json
{
  "domain": "ja.wikipedia.org",
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
    "Server: mw-web.eqiad.main-5fb6d6bf94-qbc7c"
  ],
  "cookies": [
    {},
    {
      "domain": ".wikipedia.org"
    },
    {
      "domain": ".wikipedia.org"
    },
    {
      "samesite": "none"
    },
    {
      "domain": ".wikipedia.org",
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
      "origin": "https://sub.ja.wikipedia.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ja.wikipedia.org/"
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
  "elapsed_s": 13.0,
  "rechecked": "2026-09-26 14:53 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
