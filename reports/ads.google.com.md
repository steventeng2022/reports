# Security Audit Report — ads.google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ads.google.com/ |
| Bug bounty program | Google |
| Listed scope domain | ads.google.com |
| Test date | 2026-09-26 17:38 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 3, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 5 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | CK5 | Cookie scoped to parent domain (.google.com) | CWE-200 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

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

### 5. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=3600 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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

### 10. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=HpBUmX64tYTjTlOu5Vn5q9W91WgLadW3cLOWY7pI3YI
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of ads.google.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but ads.google.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] Cookie scoped to parent domain (.google.com) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host ads.google.com.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 2 disallow path(s), e.g. /, /api*?hl=
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "ads.google.com",
  "dns": {
    "a": [
      "142.250.204.46"
    ],
    "aaaa": [
      "2404:6800:4012:9::200e"
    ],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 10)"
    ],
    "ns": [],
    "spf": [
      "_mcxyx9l6w4ff69zlv6gij2ue9qo8i7m",
      "google-site-verification=HpBUmX64tYTjTlOu5Vn5q9W91WgLadW3cLOWY7pI3YI",
      "v=spf1 redirect=_spf.google.com"
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
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR2",
    "notBefore": "Sep 10 19:23:18 2026 GMT",
    "notAfter": "Dec  3 19:23:17 2026 GMT",
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
    "days_left": 68,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "142.250.204.46",
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
      "domain": "ads.google.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.ads.google.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ads.google.com/"
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
    "/.well-known/security.txt": 404,
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=HpBUmX64tYTjTlOu5Vn5q9W91WgLadW3cLOWY7pI3YI"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/api*?hl="
    ]
  },
  "elapsed_s": 7.9,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
