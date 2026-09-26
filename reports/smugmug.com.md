# Security Audit Report — smugmug.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://smugmug.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | smugmug.com |
| Test date | 2026-09-25 10:16 UTC |
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

## Evidence (raw response observations)

```json
{
  "domain": "smugmug.com",
  "dns": {
    "a": [
      "100.52.94.3",
      "32.193.115.37",
      "3.83.200.95"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-798.awsdns-35.net.",
      "ns-1488.awsdns-58.org.",
      "ns-160.awsdns-20.com.",
      "ns-1569.awsdns-04.co.uk."
    ],
    "spf": [
      "anthropic-domain-verification-ytcjx3=3JXEHEGUIDVMUMf0uDxrNCHeS",
      "asv=b9dfbae46b15612f6607a68ae19a7e2e",
      "TAILSCALE-2SnWDnM6RXvoBqRCJXyE",
      "v=spf1 include:_spf.smugmug_com._d.easydmarc.pro ~all",
      "easydmarc-verification:c41a276a-ac1c-4df4-afb0-24d13abb4082",
      "h1-domain-verification=VswTbgZa19ikLScJDExi1oP55pEEtqbzNnXMsNAbRLGQ5pwf",
      "lovable_verification=mUkuMoOCniK09G3hpvMK",
      "miro-verification=57e9f2368bcc8d66648f3d731cb9a81eda2d084b",
      "google-site-verification=-nck5ImlodD2x9hVKFtLY2lgmH0nTzkkhqrYMGTbATQ",
      "status-page-domain-verification=2z6n94xyr5tj",
      "h1-domain-verification=WGuGC3hnnTu7E31Y7R7KZfvJtMDib9GK1dfYdJ3Uko1oBnKJ",
      "atlassian-domain-verification=TgOLLHFpQq2Vo30Hxzddllz1ji7PkMt0vV2E5B3rUCP2ICBlTYaOx4ns/CDzkVnf",
      "docusign=db2c269a-ec4f-4e67-ae5f-1ef42b248990"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;rua=mailto:c707497ded@rua.easydmarc.us;ruf=mailto:c707497ded@ruf.easydmarc.us;fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=smugmug.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Nov 27 00:00:00 2025 GMT",
    "notAfter": "Dec 25 23:59:59 2026 GMT",
    "san": [
      "smugmug.com",
      "*.smugmug.pro",
      "smugmug.pro",
      "*.smugmug.com"
    ],
    "days_left": 91,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "100.52.94.3",
    "open": []
  },
  "https": {
    "status": 502,
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
      "origin": "https://sub.smugmug.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 502
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 502",
    "/redirect?next=https://evil-auditor.example/x -> 502",
    "/go?url=https://evil-auditor.example/x -> 502",
    "/url?url=https://evil-auditor.example/x -> 502"
  ],
  "paths": {
    "/robots.txt": 502,
    "/sitemap.xml": 502,
    "/.well-known/security.txt": 502,
    "/security.txt": 502,
    "/.git/HEAD": 502,
    "/.git/config": 502,
    "/.env": 502,
    "/.htaccess": 502,
    "/wp-login.php": 502,
    "/phpmyadmin/index.php": 502,
    "/server-status": 502,
    "/api/": 502
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 55.3,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
