# Security Audit Report — adwords.google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://adwords.google.com/ |
| Bug bounty program | Google |
| Listed scope domain | adwords.google.com |
| Test date | 2026-09-25 08:21 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 2, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ESF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ESF
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "adwords.google.com",
  "dns": {
    "a": [
      "64.233.189.113",
      "64.233.189.102",
      "64.233.189.139",
      "64.233.189.101",
      "64.233.189.100",
      "64.233.189.138"
    ],
    "aaaa": [
      "2404:6800:4008:c07::8b",
      "2404:6800:4008:c07::66",
      "2404:6800:4008:c07::65",
      "2404:6800:4008:c07::8a"
    ],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx4.googlemail.com (pref 30)",
      "aspmx5.googlemail.com (pref 30)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)"
    ],
    "ns": [],
    "spf": [
      "v=spf1 redirect=google.com",
      "facebook-domain-verification=zgc5az6ty903nxj39jxl6irm320fqt"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=adwords.google.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE2",
    "notBefore": "Sep 10 19:23:26 2026 GMT",
    "notAfter": "Dec  3 19:23:25 2026 GMT",
    "san": [
      "adwords.google.com",
      "ads.google.com",
      "frame.ads.google.com",
      "*.frame.ads.google.com",
      "www.ads.google.com",
      "www.adwords.google.com",
      "admob.biz",
      "*.admob.biz",
      "admob.co.in",
      "*.admob.co.in",
      "admob.co.kr",
      "*.admob.co.kr",
      "admob.co.nz",
      "*.admob.co.nz",
      "admob.co.uk",
      "*.admob.co.uk",
      "admob.co.za",
      "*.admob.co.za",
      "admob.com",
      "*.admob.com",
      "admob.com.br",
      "*.admob.com.br",
      "admob.com.es",
      "*.admob.com.es",
      "admob.com.fr",
      "*.admob.com.fr",
      "admob.com.mx",
      "*.admob.com.mx",
      "admob.com.pt",
      "*.admob.com.pt",
      "admob.de",
      "*.admob.de",
      "admob.dk",
      "*.admob.dk",
      "admob.es",
      "*.admob.es",
      "admob.fi",
      "*.admob.fi",
      "admob.fr",
      "*.admob.fr",
      "admob.gr",
      "*.admob.gr",
      "admob.hk",
      "*.admob.hk",
      "admob.ie",
      "*.admob.ie",
      "admob.in",
      "*.admob.in",
      "admob.it",
      "*.admob.it",
      "admob.jp",
      "*.admob.jp",
      "admob.kr",
      "*.admob.kr",
      "admob.mobi",
      "*.admob.mobi",
      "admob.no",
      "*.admob.no",
      "admob.ph",
      "*.admob.ph",
      "admob.pt",
      "*.admob.pt",
      "admob.sg",
      "*.admob.sg",
      "admob.tw",
      "*.admob.tw",
      "admob.us",
      "*.admob.us",
      "admob.vn",
      "*.admob.vn",
      "adwords.google.ae",
      "adwords.google.at",
      "adwords.google.be",
      "adwords.google.ca",
      "adwords.google.ch",
      "adwords.google.cn",
      "adwords.google.co.il",
      "adwords.google.co.in",
      "adwords.google.co.jp",
      "adwords.google.co.kr",
      "adwords.google.co.nz",
      "adwords.google.co.th",
      "adwords.google.co.uk",
      "adwords.google.co.ve",
      "adwords.google.co.za",
      "adwords.google.com.ar",
      "adwords.google.com.au",
      "adwords.google.com.br",
      "adwords.google.com.gr",
      "adwords.google.com.hk",
      "adwords.google.com.ly",
      "adwords.google.com.mx",
      "adwords.google.com.my",
      "adwords.google.com.pe",
      "adwords.google.com.ph",
      "adwords.google.com.pk",
      "adwords.google.com.ru",
      "adwords.google.com.sg",
      "adwords.google.com.tr",
      "adwords.google.com.tw",
      "adwords.google.com.ua",
      "adwords.google.com.vn",
      "adwords.google.cv",
      "adwords.google.cz",
      "adwords.google.de",
      "adwords.google.dk",
      "adwords.google.es",
      "adwords.google.fi",
      "adwords.google.fr",
      "adwords.google.hu",
      "adwords.google.it",
      "adwords.google.lt",
      "adwords.google.lv",
      "adwords.google.nl",
      "adwords.google.no",
      "adwords.google.pl",
      "adwords.google.pt",
      "adwords.google.ro",
      "adwords.google.ru",
      "adwords.google.se",
      "adwords.google.sk"
    ],
    "days_left": 69,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "64.233.189.113",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: ESF"
  ],
  "cookies": [
    {
      "domain": ".google.com",
      "samesite": "none"
    },
    {
      "domain": "adwords.google.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.adwords.google.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://adwords.google.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 125.0,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
