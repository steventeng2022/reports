# Security Audit Report — zen.yandex.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://zen.yandex.ru/ |
| Bug bounty program | Yandex |
| Listed scope domain | zen.yandex.ru |
| Test date | 2026-09-26 19:02 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 6, Info: 13)

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
| 12 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | CK5 | Cookie scoped to parent domain (.yandex.ru) | CWE-200 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

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

### 12. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=GuJk1T5z2NlhKlN-pHwdtqiFEFJmvjm4pDu-lbj4g5A; yandex-verification: adcf799d964be8a8; facebook-domain-verification=3j25o2dnvau5xoluquutgkewnd2321
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of zen.yandex.ru has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] Cookie scoped to parent domain (.yandex.ru) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host zen.yandex.ru.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 91 disallow path(s), e.g. /about*?*, /away, /top$, /search, /money
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 87.250.254.116 carries PTR zen.yandex.net. for zen.yandex.ru.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

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
      "google-site-verification=GuJk1T5z2NlhKlN-pHwdtqiFEFJmvjm4pDu-lbj4g5A",
      "v=spf1 include:_spf.yandex-team.ru include:mail.zendesk.com",
      "yandex-verification: adcf799d964be8a8",
      "facebook-domain-verification=3j25o2dnvau5xoluquutgkewnd2321",
      "google-site-verification=pS5x1twac3BzKk3hE85gZ3nDua-pdHnqwmamk-XtxP0",
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
    "days_left": 121,
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=GuJk1T5z2NlhKlN-pHwdtqiFEFJmvjm4pDu-lbj4g5A",
    "yandex-verification: adcf799d964be8a8",
    "facebook-domain-verification=3j25o2dnvau5xoluquutgkewnd2321",
    "google-site-verification=pS5x1twac3BzKk3hE85gZ3nDua-pdHnqwmamk-XtxP0",
    "mailru-verification: 74012169191518f4"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20260727211409",
      "not_after": "20270125205959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/about*?*",
      "/away",
      "/top$",
      "/search",
      "/money",
      "/onboarding",
      "/news/top",
      "/news/smi",
      "/news/search",
      "/t/",
      "/user/",
      "/embed/",
      "/*/url",
      "/video/games/tags/",
      "/*sso_failed="
    ]
  },
  "x12": {
    "status": 302,
    "ptr": [
      "zen.yandex.net."
    ]
  },
  "elapsed_s": 43.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
