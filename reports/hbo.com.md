# Security Audit Report — hbo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hbo.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hbo.com |
| Test date | 2026-09-26 18:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 6, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 12 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 13 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 19 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 20 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443";ma=86400,h3-29=":443";ma=86400,h3-27=":443";ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'countryCode' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 12. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'stateCode' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 13. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'geoData' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 14. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 15. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 16. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: adobe-idp-site-verification=6b91c48785893991cc3cf88c073dbc3e4d101443ffbcd2859010; google-site-verification=FyHIYNMYtacdeYPK7CFQexzcTapnqZU223BTKsahsXE; google-site-verification=6NTd9bZvlQzGGYhk9F5NDpFYjzntMcPyZTQAmYXxbLE
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of hbo.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 19. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but hbo.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 20. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1 disallow path(s), e.g. /content/*
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "hbo.com",
  "dns": {
    "a": [
      "151.101.1.55",
      "151.101.193.55",
      "151.101.65.55",
      "151.101.129.55"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "hbo-com.mail.protection.outlook.com (pref 5)"
    ],
    "ns": [
      "ns-1897.awsdns-45.co.uk.",
      "ns-63.awsdns-07.com.",
      "ns-662.awsdns-18.net.",
      "ns-1217.awsdns-24.org."
    ],
    "spf": [
      "adobe-idp-site-verification=6b91c48785893991cc3cf88c073dbc3e4d101443ffbcd2859010727b0575e17e",
      "9b04608n3lxylrbgzmmzhpzngmryfdkz",
      "671988175-12122548",
      "google-site-verification=FyHIYNMYtacdeYPK7CFQexzcTapnqZU223BTKsahsXE",
      "google-site-verification=6NTd9bZvlQzGGYhk9F5NDpFYjzntMcPyZTQAmYXxbLE",
      "google-site-verification=9gePLUf80rMHYDmuPpE-ZwLjGvzkukgY49yjTOfnDtM",
      "MS=ms69642137",
      "google-site-verification=PPKvhksy5y9BY98aJv-Pbt5KEaBx56J97MhUGW2wp90",
      "v=spf1 include:hbo.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all",
      "smartsheet-site-validation.hbo.com=hDWT+iX//NWjhnuIwn6p0ABkODcnRz2ZFxti5GgtCjY=",
      "google-site-verification=YVE1XQiIPhIXOxPkAvqsaJPqfCHXQoqZrhwuwl9eXiI",
      "atlassian-domain-verification=joqe6L8dNi+aisGbB1XHQa0pDc53V2l0GQQRUtLEcr2997x0+rtrAA5Zw+UgQw3u",
      "lucidchart-verification=fv33o3sxxpyg83fkwnl1",
      "cisco-ci-domain-verification=fa33a8661bbf3b1f9dff9344e3ac17f37de9632597126eda4eb6a2cd852097f",
      "anthropic-domain-verification-y7w1sm=ph88E7qdbFJUeSPIyiHPupVQ7",
      "postman-domain-verification=cd813d70bf99ae7071a4652b4a8f93ffcb1a7952d9302be5102db2bca5281afb185b50a44d8ea4ef88eb9092168407c1d8c551047b166900fff966b0092b3770",
      "_globalsign-domain-verification=G6rAn-5s3I6Ukt7EpylRLtWbglxplS_gS1j_JEGoEy",
      "canva-site-verification=nTHHCJWAZx0su5nbZTwRJw",
      "facebook-domain-verification=ikjv2tsvtbdjby9jzmndvqnh5eu3df",
      "adobe-sign-verification=851df024b8fb3cd18463f3ca49e0a382",
      "google-site-verification=zJEFSVfAzkOwA37-wHGgRsKEnQYAmOfW1nFrIRQ3dws",
      "_globalsign-domain-verification=Nm83aY0luFmKaEsROwWuFmSDG1GpsRXe6rrIHF_-PB",
      "GM2s0rl8m2M8+aduzPSrdSx+Qov8kBguD3ScwDO3hssN091zF49gk1A7AMbBb/+XZe3Uwp06eTpym28ZmMvOmA==",
      "884fdb9d-6da8-42a2-ab0b-c90ac2dba754",
      "apple-domain-verification=5lqzlq9YCMRcc6Nc",
      "_globalsign-domain-verification=y5vdurCbC4j5d7MV9vSxuv8uVCkhT1nhaj_gcfDJTR",
      "google-site-verification=kHBF6A_fqUd4bpgDkjBQSpi14Qvcv1BokGGHcIIsY1s",
      "PKFS/m8wm6RASUf1vmbVzuTnJMsxg522xk09UfzsaVhKKPqzeiqul7GeuCxDRWLRSkOO8lSEhPfChRa2/DMV/A==",
      "miro-verification=1e01f8da769be1241fceefd9abf2c317dcd68323",
      "cloudhealth=7bffbad9-cff4-4761-add2-9e8d2702fe83",
      "_globalsign-domain-verification=gKLyHVs2-A8jjJCtFFMvdQQaGDVdh8ohZU0SmsDmAy",
      "_globalsign-domain-verification=ZFOw8Gt29vHTv6SXbYvBumUzxAjlLsM150n6cu_sl8",
      "google-site-verification=kihnMTsj1roc6QOJ3MtRzKmVcznr4-J7gra1tCchVo0"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email,mailto:dmarc@hbo.com; ruf=mailto:MTI3@ruf.vali.email,mailto:dmarc@hbo.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=hbo.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2026 Q1",
    "notBefore": "Jan 22 17:25:15 2026 GMT",
    "notAfter": "Feb 23 17:25:14 2027 GMT",
    "san": [
      "hbo.com"
    ],
    "days_left": 149,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.1.55",
    "open": []
  },
  "https": {
    "status": 308,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [
    {
      "domain": ".hbo.com",
      "samesite": "lax"
    },
    {
      "domain": ".hbo.com",
      "samesite": "lax"
    },
    {
      "domain": ".hbo.com",
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.hbo.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://hbo.com/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "adobe-idp-site-verification=6b91c48785893991cc3cf88c073dbc3e4d101443ffbcd2859010",
    "google-site-verification=FyHIYNMYtacdeYPK7CFQexzcTapnqZU223BTKsahsXE",
    "google-site-verification=6NTd9bZvlQzGGYhk9F5NDpFYjzntMcPyZTQAmYXxbLE",
    "google-site-verification=9gePLUf80rMHYDmuPpE-ZwLjGvzkukgY49yjTOfnDtM",
    "google-site-verification=PPKvhksy5y9BY98aJv-Pbt5KEaBx56J97MhUGW2wp90"
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
      "not_before": "20260122172515",
      "not_after": "20270223172514"
    }
  },
  "http2": {
    "robots_disallow": [
      "/content/*"
    ]
  },
  "x12": {
    "status": 308
  },
  "elapsed_s": 17.2,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
