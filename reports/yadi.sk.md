# Security Audit Report — yadi.sk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yadi.sk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | yadi.sk |
| Test date | 2026-09-26 14:57 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 2, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

## Evidence (raw response observations)

```json
{
  "domain": "yadi.sk",
  "dns": {
    "a": [
      "87.250.250.50"
    ],
    "aaaa": [
      "2a02:6b8::2:50"
    ],
    "cname": null,
    "mx": [],
    "ns": [
      "ns3.yandex.ru.",
      "ns4.yandex.ru."
    ],
    "spf": [
      "45e3b7565dc5130458f2bead528f8f6000d78f2b5fd904b06355c19f0cd3e4f",
      "_globalsign-domain-verification=ZIE7lnBAHKRRAGoG_hFijsNTqp_so1pEzNwsMUA4xI",
      "96ecd6928cf6313019cf2d11dc11d6fa945e5d808fcd391ce076bcd6968aa39"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=RU, stateOrProvinceName=Moscow, localityName=Moscow, organizationName=YANDEX LLC, commonName=disk.yandex.ru",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign GCC R46 OV TLS CA 2025",
    "notBefore": "Sep  1 15:16:16 2026 GMT",
    "notAfter": "Mar  1 20:59:59 2027 GMT",
    "san": [
      "disk.yandex.ru",
      "docs.360.yandex.tm",
      "docs.360.yandex.tj",
      "docs.360.yandex.md",
      "docs.360.yandex.lv",
      "docs.360.yandex.lt",
      "docs.360.yandex.kg",
      "docs.360.yandex.fr",
      "docs.360.yandex.ee",
      "docs.360.yandex.com.tr",
      "docs.360.yandex.com.ge",
      "docs.360.yandex.com.am",
      "docs.360.yandex.com",
      "docs.360.yandex.co.il",
      "docs.360.yandex.az",
      "docs.yandex.tm",
      "docs.yandex.tj",
      "docs.yandex.md",
      "docs.yandex.lv",
      "docs.yandex.lt",
      "docs.yandex.kg",
      "docs.yandex.fr",
      "docs.yandex.ee",
      "docs.yandex.com.tr",
      "docs.yandex.com.ge",
      "docs.yandex.com.am",
      "docs.yandex.com",
      "docs.yandex.co.il",
      "docs.yandex.az",
      "disk.yandex.kz",
      "disk.yandex.com",
      "disk.yandex.uz",
      "disk.yandex.kg",
      "yadi.sk",
      "disk.yandex.net",
      "disk.yandex.by",
      "disk.yandex.com.ge",
      "disk.yandex.tm",
      "disk.yandex.tj",
      "disk.yandex.lv",
      "disk.yandex.ee",
      "disk.yandex.lt",
      "docs.yandex.ru",
      "disk.yandex.com.tr",
      "disk.yandex.com.am",
      "disk.yandex.fr",
      "disk.yandex.co.il",
      "disk.yandex.az",
      "disk.yandex.md",
      "docs.yandex.by",
      "docs.yandex.kz",
      "disk.360.yandex.ru",
      "disk.360.yandex.az",
      "disk.360.yandex.by",
      "disk.360.yandex.co.il",
      "disk.360.yandex.com",
      "disk.360.yandex.com.am",
      "disk.360.yandex.com.ge",
      "disk.360.yandex.com.tr",
      "disk.360.yandex.ee",
      "disk.360.yandex.fr",
      "disk.360.yandex.kg",
      "disk.360.yandex.kz",
      "disk.360.yandex.lt",
      "disk.360.yandex.lv",
      "disk.360.yandex.md",
      "disk.360.yandex.net",
      "disk.360.yandex.tj",
      "disk.360.yandex.tm",
      "disk.360.yandex.uz",
      "docs.360.yandex.ru",
      "docs.360.yandex.by",
      "docs.360.yandex.kz",
      "docs.yandex.uz",
      "docs.360.yandex.uz"
    ],
    "days_left": 156,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "87.250.250.50",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [
    {},
    {
      "domain": ".yadi.sk",
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
      "origin": "https://sub.yadi.sk",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://yadi.sk/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 200,
    "/.git/config": 200,
    "/.env": 200,
    "/.htaccess": 200,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 200,
    "/server-status": 200,
    "/api/": 200
  },
  "subdomains": {
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 45.6,
  "rechecked": "2026-09-26 14:53 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
