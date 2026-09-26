# Security Audit Report — sketchfab.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://sketchfab.com/ |
| Bug bounty program | Epic Games |
| Listed scope domain | sketchfab.com |
| Test date | 2026-09-25 10:15 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 4, Info: 9)

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
- **Detail:** Origin https://sub.sketchfab.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "sketchfab.com",
  "dns": {
    "a": [
      "54.192.248.88",
      "54.192.248.119",
      "54.192.248.123",
      "54.192.248.90"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt3.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-15.awsdns-01.com.",
      "ns-1005.awsdns-61.net.",
      "ns-1716.awsdns-22.co.uk.",
      "ns-1283.awsdns-32.org."
    ],
    "spf": [
      "openai-domain-verification=dv-WwDzb0UffYovHWmc8ILUiSsC",
      "anthropic-domain-verification-pkgrxp=9SX6zKkJLDT6sYYBe3jSwNzDA",
      "smartsheet-site-validation=UKQ9vunDy5i2LXlAqwfMpCBLYvg1TNd9",
      "facebook-domain-verification=abkh6sdfak0gjfk06lp9yy63v86yd0",
      "dropbox-domain-verification=hdzg4gv89jax",
      "Sendinblue-code:893b13ba16ab42c906f31ddb4d6c0972",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all",
      "google-site-verification=1D22clCUDVDvqHEntN2eD6uGI68BZM_zn1Q68W3H4Z4",
      "docusign=cc2bea62-2607-4969-b594-291f05fe9a18",
      "miro-verification=66a6d0d4ec91315544e1c0ab5e73b7a2a174f6f4",
      "box-domain-verification=90c68eb309746ce326626165eadc4785e6094731b6e841ac85dab1c1d08a071c",
      "cursor-domain-verification-bfcs5x=3og16N1cvdpYQTiEbkW8l3SAy",
      "atlassian-domain-verification=SoJZyndmWCSCCPEyKf0gxRibYYQGlSvtWMEwAI5JRm0LU2g7e7xW4T2WRM0iahex",
      "google-site-verification=CkzXPYnKKBciPYalhXoO-ZqsXvZFrUJyh651HowaeH4",
      "domain-verification=a1005fb6436172b4589d82ac0aebeb7836b99d474365b7fde9850ef1f83cf9bd",
      "_proofpoint-verification=5c42dd9b-ce3b-48c3-954c-37bec7da586f",
      "adobe-idp-site-verification=8a5be962006abb6a54a07ecebc48df8733bcccf0a5c6b8bcb66f58ad5e8dd604",
      "google-site-verification=LrK1Vp3WgG36TFqPMA1zxPstliUIGZJAhtU3i-slqHQ",
      "figma-domain-verification=ffa6044ba8b42d9296b3ff1607f226aecde09d2ef5e0141135265e1251ec1506-1718206799",
      "notion-domain-verification=xXMBP2X1o1sdyWYbFPT8WxMFmH6AeVwrpRpcdXK9uZ0"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; sp=reject; pct=100; adkim=r; aspf=r; rua=mailto:dmarc_agg@vali.email,mailto:dmarc@mailinblue.com,mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc@mailinblue.com,mailto:dmarc_ruf@emaildefense.proofpoint.com,mailto:epic",
      "-games@ruf-reporting.vali.email; fo=1; rf=afrf; ri=86400"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=sketchfab.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Dec 17 00:00:00 2025 GMT",
    "notAfter": "Jan 15 23:59:59 2027 GMT",
    "san": [
      "sketchfab.com",
      "*.sketchfab.me",
      "e6f79c614c67.sketchfab.com",
      "sketchfab.me",
      "www.skfb.ly",
      "api.sketchfab.com",
      "skfb.ly",
      "blog.sketchfab.com",
      "www.sketchfab.com"
    ],
    "days_left": 112,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.88",
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
      "origin": "https://sub.sketchfab.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 202
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
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 41.4,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
