# Security Audit Report — wikipedia.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wikipedia.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | wikipedia.org |
| Test date | 2026-09-25 10:27 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: mw-web.eqiad.main-5fb4bc6d98-9g78b
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: mw-web.eqiad.main-5fb4bc6d98-9g78b
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "wikipedia.org",
  "dns": {
    "a": [
      "103.102.166.224"
    ],
    "aaaa": [
      "2001:df2:e500:ed1a::1"
    ],
    "cname": null,
    "mx": [
      "mx-in1001.wikimedia.org (pref 10)",
      "mx-in2001.wikimedia.org (pref 10)"
    ],
    "ns": [
      "ns1.wikimedia.org.",
      "ns0.wikimedia.org.",
      "ns2.wikimedia.org."
    ],
    "spf": [
      "v=spf1 include:_cidrs.wikimedia.org ~all",
      "google-site-verification=AMHkgs-4ViEvIJf5znZle-BSE2EPNFqM1nDJGRyn2qk",
      "yandex-verification: 35c08d23099dc863"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-rua@wikimedia.org;"
    ],
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
    "days_left": 39,
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
    "Server: mw-web.eqiad.main-5fb4bc6d98-9g78b"
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
      "origin": "https://sub.wikipedia.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://wikipedia.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 44.9,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
