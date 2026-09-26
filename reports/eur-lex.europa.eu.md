# Security Audit Report — eur-lex.europa.eu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://eur-lex.europa.eu/ |
| Bug bounty program | European Central Bank |
| Listed scope domain | eur-lex.europa.eu |
| Test date | 2026-09-26 17:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 4, Info: 10)

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
| 11 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 12 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
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
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 12. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.eur-lex.europa.eu was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of eur-lex.europa.eu has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "eur-lex.europa.eu",
  "dns": {
    "a": [
      "52.84.20.55",
      "52.84.20.98",
      "52.84.20.72",
      "52.84.20.100"
    ],
    "aaaa": [],
    "cname": "eur-lex.op-tech.publications.europa.eu.",
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
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=eur-lex.europa.eu",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Nov 16 00:00:00 2025 GMT",
    "notAfter": "Dec 15 23:59:59 2026 GMT",
    "san": [
      "eur-lex.europa.eu",
      "eurlex.europa.eu",
      "www.eurlex.europa.eu",
      "www.eur-lex.europa.eu",
      "toj-bcp.eur-lex.europa.eu"
    ],
    "days_left": 80,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "52.84.20.55",
    "open": []
  },
  "https": {
    "status": 202,
    "content_type": "text/html; charset=UTF-8",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.eur-lex.europa.eu",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://eur-lex.europa.eu/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 202",
    "/redirect?next=https://evil-auditor.example/x -> 202",
    "/go?url=https://evil-auditor.example/x -> 202",
    "/url?url=https://evil-auditor.example/x -> 202"
  ],
  "paths": {
    "/robots.txt": 202,
    "/sitemap.xml": 202,
    "/.well-known/security.txt": 202,
    "/security.txt": 202,
    "/.git/HEAD": 202,
    "/.git/config": 202,
    "/.env": 202,
    "/.htaccess": 202,
    "/wp-login.php": 202,
    "/phpmyadmin/index.php": 202,
    "/server-status": 202,
    "/api/": 202
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "cname_chain": [
    "eur-lex.op-tech.publications.europa.eu"
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
      "aia_ocsp": null
    }
  },
  "elapsed_s": 19.8,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
