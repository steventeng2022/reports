# Security Audit Report — www-01.ibm.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://www-01.ibm.com/ |
| Bug bounty program | IBM |
| Listed scope domain | www-01.ibm.com |
| Test date | 2026-09-25 10:28 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

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

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
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
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "www-01.ibm.com",
  "dns": {
    "a": [
      "23.209.217.36"
    ],
    "aaaa": [
      "2600:1417:76:584::1e89",
      "2600:1417:76:587::1e89"
    ],
    "cname": "www-01-ext.ibm.net.",
    "mx": [],
    "ns": [],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=Armonk, organizationName=International Business Machines Corporation, commonName=www.ibm.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jan  6 00:00:00 2026 GMT",
    "notAfter": "Jan  5 23:59:59 2027 GMT",
    "san": [
      "www.ibm.com",
      "1.cms.s81c.com",
      "1.cmsnew.s81c.com",
      "1.cmspoc.s81c.com",
      "1.cmsstage.s81c.com",
      "1.cmsstagenew.s81c.com",
      "1.cmstest.s81c.com",
      "1.dam.s81c.com",
      "1.damstage.s81c.com",
      "1.www.s81c.com",
      "1.wwwstage.s81c.com",
      "ap.cms.s81c.com",
      "api.marketplace.ibm.com",
      "api.www.s81c.com",
      "assets.ibm.com",
      "cdn-prod-edit.cms.ibm.net",
      "demo.marketplace.ibm.com",
      "dev-ext.assets.ibm.com",
      "dev.partnerportal.ibm.com",
      "developer.ibm.com",
      "devops-ext.assets.ibm.com",
      "eu.cms.s81c.com",
      "ibm.com",
      "infra-ext.assets.ibm.com",
      "int.partnerportal.ibm.com",
      "manage-stage.marketplace.ibm.com",
      "manage.marketplace.ibm.com",
      "mp.s81c.com",
      "myibm.ibm.com",
      "open.marketplace.ibm.com",
      "partnerportal.ibm.com",
      "platform-console.marketplace.ibm.com",
      "preprod-ext.assets.ibm.com",
      "preview.marketplace.ibm.com",
      "prod.ts-api.ibm.com",
      "stage-ext.assets.ibm.com",
      "stage.partnerportal.ibm.com",
      "test-poc.ts-api.ibm.com",
      "test.ts-api.ibm.com",
      "ts-api.ibm.com",
      "us.cms.s81c.com",
      "usmr.cms.s81c.com",
      "www-01.ibm.com",
      "www-03.ibm.com",
      "www-05.ibm.com",
      "www-06.ibm.com",
      "www-112.ibm.com",
      "www-2000.ibm.com",
      "www-356.ibm.com",
      "www-40.ibm.com",
      "www-50.ibm.com",
      "www-935.ibm.com",
      "www-946.ibm.com",
      "www-969.ibm.com",
      "www-969stage.ibm.com",
      "www-api.ibm.com",
      "www.atss001uat.at.smi.ibm.com",
      "www.developer.ibm.com",
      "www.nic.ibm",
      "wwwpoc-112.ibm.com",
      "wwwpoc.ibm.com",
      "wwwstage-api.ibm.com",
      "wwwstage.ibm.com",
      "wwwtest-112.ibm.com",
      "wwwtest.ibm.com"
    ],
    "days_left": 102,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.209.217.36",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.www-01.ibm.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www-01.ibm.com/"
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 42.5,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
