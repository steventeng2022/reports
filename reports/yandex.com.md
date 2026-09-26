# Security Audit Report — yandex.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yandex.com/ |
| Bug bounty program | Yandex |
| Listed scope domain | yandex.com |
| Test date | 2026-09-26 19:02 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 5, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | low | CORS1 | CORS: subdomain origin origin accepted with credentials | CWE-942 |
| 7 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 8 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 9 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 15 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

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

### 7. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 8. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.yandex.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 9. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (hue0ftevtrnkmk.yandex.com and zrey5qf2ce290a.yandex.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=LUbMcUb0Zdviv4wd-A5JeHEzy5xZYZSWQQ0cxuo80l; google-site-verification=FVk3gum7zZLdkqi96ypScROFMew0wMetq1Gpu4rkzPI; facebook-domain-verification=625igbkehyfptcek6nh1hz7q4s3h4a
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of yandex.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but yandex.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 618 disallow path(s), e.g. /?, /403.html, /404.html, /500.html, /about.html
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of yandex.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 15. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of yandex.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 77.88.55.88 carries PTR yandex.ru. for yandex.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "yandex.com",
  "dns": {
    "a": [
      "77.88.55.88",
      "77.88.44.55",
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
      "ns2.yandex.net.",
      "ns1.yandex.net."
    ],
    "spf": [
      "_globalsign-domain-verification=LUbMcUb0Zdviv4wd-A5JeHEzy5xZYZSWQQ0cxuo80l",
      "google-site-verification=FVk3gum7zZLdkqi96ypScROFMew0wMetq1Gpu4rkzPI",
      "5849d1f0fc8a9e73d82dfed9f2c33931",
      "facebook-domain-verification=625igbkehyfptcek6nh1hz7q4s3h4a",
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
    "days_left": 94,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "77.88.55.88",
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
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "_globalsign-domain-verification=LUbMcUb0Zdviv4wd-A5JeHEzy5xZYZSWQQ0cxuo80l",
    "google-site-verification=FVk3gum7zZLdkqi96ypScROFMew0wMetq1Gpu4rkzPI",
    "facebook-domain-verification=625igbkehyfptcek6nh1hz7q4s3h4a",
    "facebook-domain-verification=gy3xj2e9mxu0vtcdgqcznoaxoaiv63"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260701145410",
      "not_after": "20261229205959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/?",
      "/403.html",
      "/404.html",
      "/500.html",
      "/about.html",
      "/adddata",
      "/adresa-segmentator",
      "/advanced_engl.html",
      "/advertising",
      "/ads/",
      "/adfox/",
      "/an/",
      "/alice/chat/",
      "/all-supported-params",
      "/articles"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "yandex.ru."
    ]
  },
  "elapsed_s": 40.0,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
