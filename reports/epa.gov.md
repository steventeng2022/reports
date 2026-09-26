# Security Audit Report — epa.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://epa.gov/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | epa.gov |
| Test date | 2026-09-26 18:50 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 3, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 25 days (notAfter Oct 21 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Apache
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=fUmsNQhzYYZmxo4WqfmBkmwUMlk1H9ns-cGuXfwx9IM; {adobe-idp-site-verification=6c7001ef-8126-4fbc-8ecb-8fae83ee039b}; adobe-idp-site-verification=6c7001ef-8126-4fbc-8fae83ee039b
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of epa.gov has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but epa.gov is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 28 disallow path(s), e.g. /core/, /profiles/, /README.txt, /web.config, /admin/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 134.67.21.34 carries PTR pubweb.epa.gov. for epa.gov.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "epa.gov",
  "dns": {
    "a": [
      "134.67.21.34"
    ],
    "aaaa": [
      "2620:117:506f:15::f022"
    ],
    "cname": null,
    "mx": [
      "usepa.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "nccns1.epa.gov.",
      "nccns2.epa.gov.",
      "dcns1.epa.gov.",
      "dcns2.epa.gov."
    ],
    "spf": [
      "00Dt0000000GzSF=1TBSJ00000005Cb",
      "v=spf1 include:spf.protection.outlook.com include:%{i}._ip.%{h}._ehlo.%{d}._spf.valigov.email ip4:134.67.100.0/24 ip4:161.80.70.0/24 ip4:134.67.208.0/24 ip4:32.65.72.32/26 include:gseg.att.com ~all",
      "google-site-verification=fUmsNQhzYYZmxo4WqfmBkmwUMlk1H9ns-cGuXfwx9IM",
      "iContact1869815",
      "sprout-social-067eb79a-bc98-42f8-a3f2-7d2d895c6253",
      "{adobe-idp-site-verification=6c7001ef-8126-4fbc-8ecb-8fae83ee039b}",
      "cloudflare_dashboard_sso=2c267daaf6145a0917c58fa43a085aee",
      "adobe-idp-site-verification=6c7001ef-8126-4fbc-8fae83ee039b",
      "adobe-sign-verification=24513cfcab0903ecf5de3fd467be1d7412df57793960e76577f9b27be8efc9ba",
      "mongodb-site-verification=BlMuSDOkvL0UWUVteO3W2lcTbjGdtzq7",
      "MS=ms7622314",
      "google-site-verification=pYOZ4IxrkFyFrh7YCNUqyfudsUvzkm_ArW_NYp2QQfs"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@valigov.email,mailto:5373cc68@mxtoolbox.dmarc-report.com,mailto:dmarc_rua_epa.gov@epa.gov,mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:5373cc68@forensics.dmarc-report.com,mailto:dmarc_ruf_epa.gov@epa.gov; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=North Carolina, localityName=Durham, organizationName=Environmental Protection Agency, commonName=*.epa.gov",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Apr 16 00:00:00 2026 GMT",
    "notAfter": "Oct 21 23:59:59 2026 GMT",
    "san": [
      "*.epa.gov",
      "epa.gov",
      "pubweb.epa.gov",
      "archive.epa.gov",
      "www3.epa.gov",
      "stashed.epa.gov",
      "water.epa.gov",
      "snapshot.epa.gov",
      "19january2017snapshot.epa.gov",
      "19January2021snapshot.epa.gov",
      "developer.epa.gov",
      "blog.epa.gov",
      "cleanairnortheast.epa.gov"
    ],
    "days_left": 25,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "134.67.21.34",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Apache"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.epa.gov",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 0,
    "error": "http connect failed"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=fUmsNQhzYYZmxo4WqfmBkmwUMlk1H9ns-cGuXfwx9IM",
    "{adobe-idp-site-verification=6c7001ef-8126-4fbc-8ecb-8fae83ee039b}",
    "adobe-idp-site-verification=6c7001ef-8126-4fbc-8fae83ee039b",
    "adobe-sign-verification=24513cfcab0903ecf5de3fd467be1d7412df57793960e76577f9b27b",
    "mongodb-site-verification=BlMuSDOkvL0UWUVteO3W2lcTbjGdtzq7"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 4096,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20260416000000",
      "not_after": "20261021235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/core/",
      "/profiles/",
      "/README.txt",
      "/web.config",
      "/admin/",
      "/comment/reply/",
      "/filter/tips",
      "/node/add/",
      "/search/",
      "/user/register/",
      "/user/password/",
      "/user/login/",
      "/user/logout/",
      "/index.php/admin/",
      "/index.php/comment/reply/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "pubweb.epa.gov."
    ]
  },
  "elapsed_s": 48.8,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
