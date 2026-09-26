# Security Audit Report — yandex.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yandex.com/ |
| Bug bounty program | Yandex |
| Listed scope domain | yandex.com |
| Test date | 2026-09-25 10:29 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 1, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | low | CORS1 | CORS: subdomain origin origin accepted with credentials | CWE-942 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 5. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 6. [LOW] CORS: subdomain origin origin accepted with credentials (`CORS1`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.yandex.com -> Access-Control-Allow-Origin: https://sub.yandex.com, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

## Evidence (raw response observations)

```json
{
  "domain": "yandex.com",
  "dns": {
    "a": [
      "77.88.44.55",
      "77.88.55.88",
      "5.255.255.77"
    ],
    "aaaa": [
      "2a02:6b8:a::a"
    ],
    "cname": null,
    "mx": [
      "mx.yandex.ru (pref 10)"
    ],
    "ns": [
      "ns1.yandex.net.",
      "ns2.yandex.net."
    ],
    "spf": [
      "google-site-verification=FVk3gum7zZLdkqi96ypScROFMew0wMetq1Gpu4rkzPI",
      "_globalsign-domain-verification=LUbMcUb0Zdviv4wd-A5JeHEzy5xZYZSWQQ0cxuo80l",
      "facebook-domain-verification=625igbkehyfptcek6nh1hz7q4s3h4a",
      "5849d1f0fc8a9e73d82dfed9f2c33931",
      "facebook-domain-verification=gy3xj2e9mxu0vtcdgqcznoaxoaiv63",
      "v=spf1 redirect=_spf.yandex.ru"
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
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "Yandex — fast Internet search"
  },
  "mixed_content": [],
  "cookies": [
    {
      "domain": "yandex.com",
      "samesite": "none"
    },
    {
      "domain": "yandex.com",
      "samesite": "none"
    },
    {
      "domain": "yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
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
      "origin": "https://sub.yandex.com",
      "acao": "https://sub.yandex.com",
      "acac": "true"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://yandex.com/"
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
  "elapsed_s": 41.9,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
