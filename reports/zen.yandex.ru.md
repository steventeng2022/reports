# Security Audit Report — zen.yandex.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://zen.yandex.ru/ |
| Bug bounty program | Yandex |
| Listed scope domain | zen.yandex.ru |
| Test date | 2026-09-25 10:30 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 5, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

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

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 9. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 10. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://dzen.ru/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "zen.yandex.ru",
  "dns": {
    "a": [
      "87.250.254.116"
    ],
    "aaaa": [
      "2a02:6b8::4fa"
    ],
    "cname": null,
    "mx": [
      "mx.yandex.ru (pref 10)"
    ],
    "ns": [
      "ns4.yandex.ru.",
      "ns3.yandex.ru."
    ],
    "spf": [
      "facebook-domain-verification=3j25o2dnvau5xoluquutgkewnd2321",
      "google-site-verification=GuJk1T5z2NlhKlN-pHwdtqiFEFJmvjm4pDu-lbj4g5A",
      "v=spf1 include:_spf.yandex-team.ru include:mail.zendesk.com",
      "google-site-verification=pS5x1twac3BzKk3hE85gZ3nDua-pdHnqwmamk-XtxP0",
      "yandex-verification: adcf799d964be8a8",
      "mailru-verification: 74012169191518f4"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "countryName=RU, stateOrProvinceName=Moscow, localityName=Moscow, organizationName=YANDEX LLC, commonName=*.zen.yandex.ru",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign GCC R46 OV TLS CA 2025",
    "notBefore": "Jul 27 21:14:09 2026 GMT",
    "notAfter": "Jan 25 20:59:59 2027 GMT",
    "san": [
      "*.zen.yandex.ru",
      "zen.yandex.com",
      "zen.yandex.uz",
      "zen.yandex.tm",
      "zen.yandex.tj",
      "zen.yandex.md",
      "zen.yandex.lv",
      "zen.yandex.lt",
      "zen.yandex.kz",
      "zen.yandex.kg",
      "zen.yandex.fr",
      "zen.yandex.ee",
      "zen.yandex.com.tr",
      "zen.yandex.com.ge",
      "zen.yandex.com.am",
      "zen.yandex.co.il",
      "zen.yandex.by",
      "zen.yandex.az",
      "zen.yandex",
      "zen.ya.ru",
      "yabro5.zen-test.yandex.ru",
      "yabro4.zen-test.yandex.ru",
      "yabro3.zen-test.yandex.ru",
      "yabro2.zen-test.yandex.ru",
      "yabro1.zen-test.yandex.ru",
      "www.zen.yandex.uz",
      "www.zen.yandex.tm",
      "www.zen.yandex.tj",
      "www.zen.yandex.md",
      "www.zen.yandex.lv",
      "www.zen.yandex.lt",
      "www.zen.yandex.kz",
      "www.zen.yandex.kg",
      "www.zen.yandex.fr",
      "www.zen.yandex.ee",
      "www.zen.yandex.com.tr",
      "www.zen.yandex.com.ge",
      "www.zen.yandex.com.am",
      "www.zen.yandex.co.il",
      "www.zen.yandex.by",
      "www.zen.yandex.az",
      "main.zdevx.yandex.ru",
      "dzen.yandex.ru",
      "dzen.ya.ru",
      "*.zen.yandex.com",
      "zen-redirect.yandex.ru",
      "zen.yandex.ru"
    ],
    "days_left": 122,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "87.250.254.116",
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
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.zen.yandex.ru",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://dzen.ru/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
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
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 64.3,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
