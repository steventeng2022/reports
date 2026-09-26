# Security Audit Report — britannica.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://britannica.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | britannica.com |
| Test date | 2026-09-26 18:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | CT1 | 41 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 17 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: awselb/2.0
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=3qlcdPLjaLxZmTfGmv2-7hXoRu7HWw7Sx--a2KgIoN0; google-site-verification=k10aAIZQu5EjFbrh-ABW-9q9phYyigXf-211snaxdg4; google-site-verification=iCsMOBxTnqow6GNvW0LQ292qIMjLqMXwpQ6tOfIZgY4
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of britannica.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 2 disallow path(s), e.g. /search, /cdn-cgi/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 100.57.38.39 carries PTR ec2-100-57-38-39.compute-1.amazonaws.com. for britannica.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] 41 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: cdn.britannica.com, cdn.email.britannica.com, fundamentals.kids.dev.britannica.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 17. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: fundamentals.kids.dev.britannica.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "britannica.com",
  "dns": {
    "a": [
      "100.57.38.39",
      "100.50.175.67"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [],
    "ns": [
      "ns-1567.awsdns-03.co.uk.",
      "ns-829.awsdns-39.net.",
      "ns-1050.awsdns-03.org.",
      "ns-243.awsdns-30.com."
    ],
    "spf": [
      "google-site-verification=3qlcdPLjaLxZmTfGmv2-7hXoRu7HWw7Sx--a2KgIoN0",
      "google-site-verification=k10aAIZQu5EjFbrh-ABW-9q9phYyigXf-211snaxdg4",
      "google-site-verification=iCsMOBxTnqow6GNvW0LQ292qIMjLqMXwpQ6tOfIZgY4",
      "ca3-34d513380a624c15b1894f20512d2ca8",
      "ca3-5187b5f7e89c48ce9ac11ac4ad4ba681",
      "facebook-domain-verification=yx5oj1072bsq69m7blcnrkktdu6h4h",
      "v=spf1 include:_spf.google.com exists:%{i}._spf.sparkpostmail.com ~all"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; fo=1; rua=mailto:d6cbe1b8@in.mailhardener.com; ruf=mailto:d6cbe1b8@in.mailhardener.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=*.britannica.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jul 12 00:00:00 2026 GMT",
    "notAfter": "Jan 25 23:59:59 2027 GMT",
    "san": [
      "*.britannica.com",
      "britannica.com"
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
    "ip": "100.57.38.39",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.britannica.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.britannica.com:443/"
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
    "source": "certspotter",
    "count": 41,
    "notable": [
      "cdn.britannica.com",
      "cdn.email.britannica.com",
      "fundamentals.kids.dev.britannica.com"
    ],
    "sample": [
      "account-service-eb500.dev-ext.britannica.com",
      "account-service-feat-read-postgres.dev-ext.britannica.com",
      "account-service-frankrobenalt.dev-ext.britannica.com",
      "account-service-hono-test.dev-ext.britannica.com",
      "account-service-rwalters.dev-ext.britannica.com",
      "account-service-ryan.dev-ext.britannica.com",
      "account-service-staging.britannica.com",
      "account-service-v2.dev-ext.britannica.com",
      "account-service.britannica.com",
      "addev.email.britannica.com",
      "advertise.britannica.com",
      "bc-script.britannica.com",
      "britannica.com",
      "cam.britannica.com",
      "cdn-dev.britannica.com",
      "cdn-qa.britannica.com",
      "cdn.britannica.com",
      "cdn.email.britannica.com",
      "depot-dev.dev-ext.britannica.com",
      "depot-qa.qa-ext.britannica.com"
    ],
    "dangling": [
      "fundamentals.kids.dev.britannica.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=3qlcdPLjaLxZmTfGmv2-7hXoRu7HWw7Sx--a2KgIoN0",
    "google-site-verification=k10aAIZQu5EjFbrh-ABW-9q9phYyigXf-211snaxdg4",
    "google-site-verification=iCsMOBxTnqow6GNvW0LQ292qIMjLqMXwpQ6tOfIZgY4",
    "facebook-domain-verification=yx5oj1072bsq69m7blcnrkktdu6h4h"
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
      "not_before": "20260712000000",
      "not_after": "20270125235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/search",
      "/cdn-cgi/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-100-57-38-39.compute-1.amazonaws.com."
    ]
  },
  "elapsed_s": 31.8,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
