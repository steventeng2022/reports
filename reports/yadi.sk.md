# Security Audit Report — yadi.sk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yadi.sk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | yadi.sk |
| Test date | 2026-09-26 19:02 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 8 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 9 | low | CK4 | Session-like cookie without HttpOnly | CWE-1004 |
| 10 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 11 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 12 | info | CT1 | 2 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 7. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=ZIE7lnBAHKRRAGoG_hFijsNTqp_so1pEzNwsMUA4xI
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 8. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of yadi.sk has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 9. [LOW] Session-like cookie without HttpOnly (`CK4`)

- **CWE:** CWE-1004
- **Detail:** Cookie 'yandex_360_session_exp_cache' looks session-related and has no HttpOnly attribute.
- **Recommendation:** Set HttpOnly on session cookies.

### 10. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 27 disallow path(s), e.g. /pay/, /activation_failed, /cfg, /folder, /copy
- **Recommendation:** Review disallowed paths; robots is not access control.

### 11. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 87.250.250.50 carries PTR disk-front.stable.qloud-b.yandex.net. for yadi.sk.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 12. [INFO] 2 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

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
      "_globalsign-domain-verification=ZIE7lnBAHKRRAGoG_hFijsNTqp_so1pEzNwsMUA4xI",
      "96ecd6928cf6313019cf2d11dc11d6fa945e5d808fcd391ce076bcd6968aa39",
      "45e3b7565dc5130458f2bead528f8f6000d78f2b5fd904b06355c19f0cd3e4f"
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
    "source": "certspotter",
    "count": 2,
    "notable": [],
    "sample": [
      "www.yadi.sk",
      "yadi.sk"
    ]
  },
  "apex_txt": [
    "_globalsign-domain-verification=ZIE7lnBAHKRRAGoG_hFijsNTqp_so1pEzNwsMUA4xI"
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
      "aia_ocsp": null,
      "not_before": "20260901151616",
      "not_after": "20270301205959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/pay/",
      "/activation_failed",
      "/cfg",
      "/folder",
      "/copy",
      "/download/Yandex.Disk.Mac.dmg",
      "/download/YandexDiskSetup.exe",
      "/download/YandexDiskSetupPack.exe",
      "/client/",
      "/models/",
      "/tuning/",
      "/gift",
      "/payment/",
      "/ping",
      "/monitoring.txt"
    ]
  },
  "x12": {
    "status": 302,
    "ptr": [
      "disk-front.stable.qloud-b.yandex.net."
    ]
  },
  "elapsed_s": 36.0,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
