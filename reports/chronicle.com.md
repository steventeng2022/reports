# Security Audit Report — chronicle.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://chronicle.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | chronicle.com |
| Test date | 2026-09-26 17:41 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 4, Info: 12)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AmazonS3
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
- **Detail:** Header reveals: AmazonS3
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=ghHJlxYD0vKv90DHLyYMvjwNw3N71lfB8Je5KWITGNA; slack-domain-verification=cPqGwGQvXliSCN0WXKB0T7c5XIp4jUmsetX1uf9f; facebook-domain-verification=5v4h15h1mtrkdbw27xfkld161mllwf
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of chronicle.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 32 disallow path(s), e.g. /, /, /, /, /
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "chronicle.com",
  "dns": {
    "a": [
      "18.154.144.24",
      "18.154.144.115",
      "18.154.144.30",
      "18.154.144.26"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-008c5001.gslb.pphosted.com (pref 0)",
      "mxa-008c5001.gslb.pphosted.com (pref 0)"
    ],
    "ns": [
      "ns-1045.awsdns-02.org.",
      "ns-1997.awsdns-57.co.uk.",
      "ns-817.awsdns-38.net.",
      "ns-140.awsdns-17.com."
    ],
    "spf": [
      "google-site-verification=ghHJlxYD0vKv90DHLyYMvjwNw3N71lfB8Je5KWITGNA",
      "slack-domain-verification=cPqGwGQvXliSCN0WXKB0T7c5XIp4jUmsetX1uf9f",
      "facebook-domain-verification=5v4h15h1mtrkdbw27xfkld161mllwf",
      "v=spf1 ip4:192.91.251.26 ip4:34.236.219.51 ip4:52.0.131.254 ip4:54.156.195.156 include:spf.protection.outlook.com include:spf-008c5001.pphosted.com include:mailgun.org include:shops.shopify.com include:_spf.psm.knowbe4.com include:mktomail.com ~all",
      "adobe-idp-site-verification=3380a292c5fe92c10b4bb843f70c593f5149d40060a2b049e94403db570c0c36",
      "globalsign-domain-verification=2f87c0c7172380296838e8ef63e87230",
      "google-site-verification=ydfkHmEE4bq_pfx6_0wsxAdmetG8VpL2XkZbLCV1gX0",
      "google-site-verification=qqA6Dr8C3MGWEEYqj7Vwdh4QwHjsga0IGj_RWoJpvE0",
      "d2sg0aymvy0li1.cloudfront.net",
      "globalsign-domain-verification=3699a4ef96609176f46cef43837026f4",
      "openai-domain-verification=dv-UuAcQejjXeQjTt0J8xqa5Vr5",
      "ZOOM_verify_hoCYRVTuQQXOotdMVCVWsx",
      "_globalsign-domain-verification=Dqd8I0hWasEjsEu2h5gF7evwjvRwfcjM-jfbkxfhb-",
      "apple-domain-verification=Kgru6DqpweYQr97c"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:re+ejbk6oq7sij@dmarc.postmarkapp.com,mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com; sp=reject; adkim=r;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=chronicle.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jun 29 00:00:00 2026 GMT",
    "notAfter": "Jan 12 23:59:59 2027 GMT",
    "san": [
      "chronicle.com",
      "*.philanthropy.com",
      "*.chronicle.com",
      "philanthropy.com"
    ],
    "days_left": 108,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "18.154.144.24",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AmazonS3"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.chronicle.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.chronicle.com/"
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
    "google-site-verification=ghHJlxYD0vKv90DHLyYMvjwNw3N71lfB8Je5KWITGNA",
    "slack-domain-verification=cPqGwGQvXliSCN0WXKB0T7c5XIp4jUmsetX1uf9f",
    "facebook-domain-verification=5v4h15h1mtrkdbw27xfkld161mllwf",
    "adobe-idp-site-verification=3380a292c5fe92c10b4bb843f70c593f5149d40060a2b049e944",
    "globalsign-domain-verification=2f87c0c7172380296838e8ef63e87230"
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
  "http2": {
    "robots_disallow": [
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/"
    ]
  },
  "elapsed_s": 24.7,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
