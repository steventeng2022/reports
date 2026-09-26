# Security Audit Report — pinterest.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pinterest.co.uk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | pinterest.co.uk |
| Test date | 2026-09-25 10:07 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 3, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "pinterest.co.uk",
  "dns": {
    "a": [
      "151.101.0.84",
      "151.101.128.84",
      "151.101.192.84",
      "151.101.64.84"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      " (pref 0)"
    ],
    "ns": [
      "ns5.pinterest.com.",
      "ns6.pinterest.com.",
      "ns9.pinterest.com.",
      "ns10.pinterest.com."
    ],
    "spf": [
      "mhxfstw3wx05mwdx3t5rvzn9l2vzl4dj",
      "v=spf1 redirect=_spf.pinterest.co.uk",
      "google-site-verification=Su8wwHIm6Mx-tKyM5HK1tqLUhLjrSugIfuBpqWFN4dM",
      "vhyf45hfd6f2wk3jlqw9r483bz8ch7l9"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; adkim=s; aspf=s;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Francisco, organizationName=Pinterest, Inc., commonName=*.pinterest.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Aug 13 00:00:00 2026 GMT",
    "notAfter": "Feb 26 23:59:59 2027 GMT",
    "san": [
      "*.pinterest.com",
      "*.pinimg.com",
      "*.pinterest.info",
      "*.pinterest.engineering",
      "*.pinterestmail.com",
      "*.pinterest.at",
      "*.pinterest.ch",
      "*.pinterest.de",
      "*.pinterest.dk",
      "*.pinterest.ie",
      "*.pinterest.jp",
      "*.pinterest.kr",
      "*.pinterest.mx",
      "*.pinterest.pt",
      "*.pinterest.se",
      "*.pinterest.co.at",
      "*.pinterest.co.kr",
      "*.pinterest.co.uk",
      "*.pinterest.com.mx",
      "pin.it",
      "pinterest.com",
      "pinimg.com",
      "pinterest.info",
      "pinterest.engineering",
      "pinterestmail.com",
      "pinterest.at",
      "pinterest.ch",
      "pinterest.de",
      "pinterest.dk",
      "pinterest.ie",
      "pinterest.jp",
      "pinterest.kr",
      "pinterest.mx",
      "pinterest.pt",
      "pinterest.se",
      "pinterest.co.at",
      "pinterest.co.kr",
      "pinterest.co.uk",
      "pinterest.com.mx",
      "*.pinterest.ca",
      "*.pinterest.fr",
      "pinterest.ca",
      "pinterest.fr",
      "pinterest.com.au",
      "*.pinterest.com.au",
      "pinterest.nz",
      "*.pinterest.nz",
      "pinterest.es",
      "*.pinterest.es",
      "pinterest.cl",
      "*.pinterest.cl",
      "pinterest.ph",
      "*.pinterest.ph",
      "pinterest.in",
      "*.pinterest.in",
      "pinterest.co.in",
      "*.pinterest.co.in",
      "pinterest.be",
      "*.pinterest.be",
      "pinterest.pe",
      "*.pinterest.pe",
      "pinterest.co",
      "*.pinterest.co",
      "pinterest.com.py",
      "*.pinterest.com.py",
      "pinterest.com.bo",
      "*.pinterest.com.bo",
      "pinterest.com.ec",
      "*.pinterest.com.ec",
      "pinterest.ec",
      "*.pinterest.ec",
      "pinterest.hu",
      "*.pinterest.hu",
      "pinterest.com.vn",
      "*.pinterest.com.vn",
      "pinterest.it",
      "*.pinterest.it",
      "pinterest.com.pe",
      "*.pinterest.com.pe",
      "pinterest.com.uy",
      "*.pinterest.com.uy",
      "pinterest.co.nz",
      "*.pinterest.co.nz",
      "pinterest.uk",
      "*.pinterest.uk",
      "pinterest.vn",
      "*.pinterest.vn",
      "pinterest.id",
      "*.pinterest.id",
      "pinterest.th",
      "*.pinterest.th",
      "pinterest.tw",
      "*.pinterest.tw",
      "pinterest.nl",
      "*.pinterest.nl",
      "*.testing.pinterest.com"
    ],
    "days_left": 154,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.0.84",
    "open": []
  },
  "https": {
    "status": 308,
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
      "origin": "https://sub.pinterest.co.uk",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 308,
    "location": "https://pinterest.co.uk/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 308",
    "/redirect?next=https://evil-auditor.example/x -> 308",
    "/go?url=https://evil-auditor.example/x -> 308",
    "/url?url=https://evil-auditor.example/x -> 308"
  ],
  "paths": {
    "/robots.txt": 308,
    "/sitemap.xml": 308,
    "/.well-known/security.txt": 308,
    "/security.txt": 308,
    "/.git/HEAD": 308,
    "/.git/config": 308,
    "/.env": 308,
    "/.htaccess": 308,
    "/wp-login.php": 308,
    "/phpmyadmin/index.php": 308,
    "/server-status": 308,
    "/api/": 308
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 26.9,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
