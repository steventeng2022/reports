# Security Audit Report — hbo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hbo.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hbo.com |
| Test date | 2026-09-26 23:29 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 7, Info: 15)

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
| 18 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 19 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 20 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 21 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 22 | low | H21 | HSTS does not cover subdomains | CWE-319 |

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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=kihnMTsj1roc6QOJ3MtRzKmVcznr4-J7gra1tCchVo0; _globalsign-domain-verification=G6rAn-5s3I6Ukt7EpylRLtWbglxplS_gS1j_JEGoEy; google-site-verification=PPKvhksy5y9BY98aJv-Pbt5KEaBx56J97MhUGW2wp90
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2026q1 -> http-400
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 19. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but hbo.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 20. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1 disallow path(s), e.g. /content/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 21. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for hbo.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 22. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on hbo.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of hbo.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

## Evidence (raw response observations)

```json
{
  "domain": "hbo.com",
  "dns": {
    "a": [
      "151.101.193.55",
      "151.101.1.55",
      "151.101.65.55",
      "151.101.129.55"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "hbo-com.mail.protection.outlook.com (pref 5)"
    ],
    "ns": [
      "ns-1217.awsdns-24.org.",
      "ns-1897.awsdns-45.co.uk.",
      "ns-662.awsdns-18.net.",
      "ns-63.awsdns-07.com."
    ],
    "caa": [],
    "spf": [
      "671988175-12122548",
      "google-site-verification=kihnMTsj1roc6QOJ3MtRzKmVcznr4-J7gra1tCchVo0",
      "_globalsign-domain-verification=G6rAn-5s3I6Ukt7EpylRLtWbglxplS_gS1j_JEGoEy",
      "google-site-verification=PPKvhksy5y9BY98aJv-Pbt5KEaBx56J97MhUGW2wp90",
      "PKFS/m8wm6RASUf1vmbVzuTnJMsxg522xk09UfzsaVhKKPqzeiqul7GeuCxDRWLRSkOO8lSEhPfChRa2/DMV/A==",
      "google-site-verification=9gePLUf80rMHYDmuPpE-ZwLjGvzkukgY49yjTOfnDtM",
      "google-site-verification=kHBF6A_fqUd4bpgDkjBQSpi14Qvcv1BokGGHcIIsY1s",
      "_globalsign-domain-verification=ZFOw8Gt29vHTv6SXbYvBumUzxAjlLsM150n6cu_sl8",
      "anthropic-domain-verification-y7w1sm=ph88E7qdbFJUeSPIyiHPupVQ7",
      "apple-domain-verification=5lqzlq9YCMRcc6Nc",
      "google-site-verification=FyHIYNMYtacdeYPK7CFQexzcTapnqZU223BTKsahsXE",
      "884fdb9d-6da8-42a2-ab0b-c90ac2dba754",
      "adobe-sign-verification=851df024b8fb3cd18463f3ca49e0a382",
      "miro-verification=1e01f8da769be1241fceefd9abf2c317dcd68323",
      "postman-domain-verification=cd813d70bf99ae7071a4652b4a8f93ffcb1a7952d9302be5102db2bca5281afb185b50a44d8ea4ef88eb9092168407c1d8c551047b166900fff966b0092b3770",
      "canva-site-verification=nTHHCJWAZx0su5nbZTwRJw",
      "MS=ms69642137",
      "google-site-verification=YVE1XQiIPhIXOxPkAvqsaJPqfCHXQoqZrhwuwl9eXiI",
      "adobe-idp-site-verification=6b91c48785893991cc3cf88c073dbc3e4d101443ffbcd2859010727b0575e17e",
      "cloudhealth=7bffbad9-cff4-4761-add2-9e8d2702fe83",
      "lucidchart-verification=fv33o3sxxpyg83fkwnl1",
      "smartsheet-site-validation.hbo.com=hDWT+iX//NWjhnuIwn6p0ABkODcnRz2ZFxti5GgtCjY=",
      "_globalsign-domain-verification=Nm83aY0luFmKaEsROwWuFmSDG1GpsRXe6rrIHF_-PB",
      "facebook-domain-verification=ikjv2tsvtbdjby9jzmndvqnh5eu3df",
      "_globalsign-domain-verification=y5vdurCbC4j5d7MV9vSxuv8uVCkhT1nhaj_gcfDJTR",
      "atlassian-domain-verification=joqe6L8dNi+aisGbB1XHQa0pDc53V2l0GQQRUtLEcr2997x0+rtrAA5Zw+UgQw3u",
      "_globalsign-domain-verification=gKLyHVs2-A8jjJCtFFMvdQQaGDVdh8ohZU0SmsDmAy",
      "google-site-verification=zJEFSVfAzkOwA37-wHGgRsKEnQYAmOfW1nFrIRQ3dws",
      "v=spf1 include:hbo.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all",
      "9b04608n3lxylrbgzmmzhpzngmryfdkz",
      "cisco-ci-domain-verification=fa33a8661bbf3b1f9dff9344e3ac17f37de9632597126eda4eb6a2cd852097f",
      "google-site-verification=6NTd9bZvlQzGGYhk9F5NDpFYjzntMcPyZTQAmYXxbLE",
      "GM2s0rl8m2M8+aduzPSrdSx+Qov8kBguD3ScwDO3hssN091zF49gk1A7AMbBb/+XZe3Uwp06eTpym28ZmMvOmA=="
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
    "ip": "151.101.193.55",
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
    "google-site-verification=kihnMTsj1roc6QOJ3MtRzKmVcznr4-J7gra1tCchVo0",
    "_globalsign-domain-verification=G6rAn-5s3I6Ukt7EpylRLtWbglxplS_gS1j_JEGoEy",
    "google-site-verification=PPKvhksy5y9BY98aJv-Pbt5KEaBx56J97MhUGW2wp90",
    "google-site-verification=9gePLUf80rMHYDmuPpE-ZwLjGvzkukgY49yjTOfnDtM",
    "google-site-verification=kHBF6A_fqUd4bpgDkjBQSpi14Qvcv1BokGGHcIIsY1s"
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
      "aia_ocsp": "http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2026q1",
      "serial": 2005217483259575983192283361378749896,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.globalsign.com/ca/gsatlasr3dvtlsca2026q1.crl"
      ],
      "subject_dn": "3110300e06035504030c0768626f2e636f6d",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312e302c06035504031325476c6f62616c5369676e2041746c617320523320445620544c532043412032303236205131",
      "not_before": "20260122172515",
      "not_after": "20270223172514"
    },
    "ocsp": "http-400"
  },
  "http2": {
    "robots_disallow": [
      "/content/*"
    ]
  },
  "x12": {
    "status": 308
  },
  "x13": {
    "root_status": 308,
    "root_location": "https://www.hbo.com/",
    "http_status": 301,
    "p404_status": 308,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 308,
    "hsts": "max-age=31536000;",
    "crl": {
      "url": "http://crl.globalsign.com/ca/gsatlasr3dvtlsca2026q1.crl",
      "status": 200
    }
  },
  "elapsed_s": 22.0,
  "rechecked": "2026-09-26 23:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- Findings are reported against the public program scope; submission through the program tracker is pending.
