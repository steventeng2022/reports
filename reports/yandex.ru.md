# Security Audit Report — yandex.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yandex.ru/ |
| Bug bounty program | Yandex |
| Listed scope domain | yandex.ru |
| Test date | 2026-09-25 10:29 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 3, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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

## Evidence (raw response observations)

```json
{
  "domain": "yandex.ru",
  "dns": {
    "a": [
      "77.88.44.55",
      "5.255.255.77",
      "77.88.55.88"
    ],
    "aaaa": [
      "2a02:6b8:a::a"
    ],
    "cname": null,
    "mx": [
      "mx.yandex.ru (pref 10)"
    ],
    "ns": [
      "ns1.yandex.ru.",
      "ns2.yandex.ru."
    ],
    "spf": [
      "mailru-verification: 530c425b1458283e",
      "MS=ms75457885",
      "have-i-been-pwned-verification=13c7b50cd0b12f85dabe796e6178fb74",
      "v=spf1 redirect=_spf.yandex.ru",
      "google-site-verification=bDiyjBjCnMbct5cB1XZXOj5gQ0YcatJqTZUxFBo55nE",
      "facebook-domain-verification=e750ewnqm68u4f83wvp6qp7iiphkj0",
      "google-site-verification=Xj1hw8lKZK7dkCP6SCfNi98SvjacNHoNCVrFbJCZfio"
    ],
    "dmarc": [
      "v=DMARC1; p=none; fo=1; rua=mailto:dmarc_agg@auth.returnpath.net,mailto:dmarc-rua@yandex.ru; ruf=mailto:dmarc_afrf@auth.returnpath.net"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=RU, stateOrProvinceName=Moscow, localityName=Moscow, organizationName=YANDEX LLC, commonName=*.yandex.tr",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign ECC OV SSL CA 2018",
    "notBefore": "Jul  1 14:54:10 2026 GMT",
    "notAfter": "Dec 29 20:59:59 2026 GMT",
    "san": [
      "*.yandex.tr",
      "xn--d1acpjx3f.xn--p1ai",
      "*.xn--d1acpjx3f.xn--p1ai",
      "yandex.aero",
      "*.yandex.aero",
      "yandex.jobs",
      "*.yandex.jobs",
      "yandex.net",
      "*.yandex.net",
      "yandex.org",
      "*.yandex.org",
      "yandex.de",
      "*.yandex.de",
      "ya.ru",
      "*.ya.ru",
      "yandex.it",
      "*.yandex.it",
      "yandex.uz",
      "*.yandex.uz",
      "yandex.tm",
      "*.yandex.tm",
      "yandex.tj",
      "*.yandex.tj",
      "yandex.ru",
      "*.yandex.ru",
      "yandex.md",
      "*.yandex.md",
      "yandex.lv",
      "*.yandex.lv",
      "yandex.lt",
      "*.yandex.lt",
      "yandex.kz",
      "*.yandex.kz",
      "yandex.fr",
      "*.yandex.fr",
      "yandex.ee",
      "*.yandex.ee",
      "yandex.com.tr",
      "*.yandex.com.tr",
      "yandex.com.ge",
      "*.yandex.com.ge",
      "yandex.com.am",
      "*.yandex.com.am",
      "yandex.com",
      "*.yandex.com",
      "yandex.co.il",
      "*.yandex.co.il",
      "yandex.by",
      "*.yandex.by",
      "yandex.az",
      "*.yandex.az",
      "yandex.tr"
    ],
    "days_left": 95,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "77.88.44.55",
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
      "domain": ".yandex.ru",
      "samesite": "none"
    },
    {
      "domain": ".yandex.ru",
      "samesite": "none"
    },
    {
      "domain": ".yandex.ru",
      "samesite": "none"
    },
    {
      "domain": ".yandex.ru",
      "samesite": "none"
    },
    {
      "domain": ".yandex.ru",
      "samesite": "none"
    },
    {
      "domain": ".yandex.ru",
      "samesite": "none"
    },
    {
      "domain": ".yandex.ru",
      "samesite": "none"
    },
    {
      "domain": ".yandex.ru",
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
      "origin": "https://sub.yandex.ru",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://yandex.ru/"
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
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 40.2,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
