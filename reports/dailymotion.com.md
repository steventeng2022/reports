# Security Audit Report — dailymotion.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dailymotion.com/ |
| Bug bounty program | Dailymotion |
| Listed scope domain | dailymotion.com |
| Test date | 2026-09-25 09:12 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
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

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 30 days (notAfter Oct 25 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: DMS/1.0.42
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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
- **Detail:** Header reveals: DMS/1.0.42
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
  "domain": "dailymotion.com",
  "dns": {
    "a": [
      "195.8.215.136"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-009c2301.gslb.pphosted.com (pref 10)",
      "mxb-009c2301.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "a.dailymotion.com.",
      "b.dailymotion.com."
    ],
    "spf": [
      "apple-domain-verification=Xc0pXSUjiGdd6fzI",
      "anthropic-domain-verification-c1804p=NXPXkMxpSDDbn8bTInhn5Ajb7",
      "notion-domain-verification=uvbWKKeyZnS8S7Wbx92ycOmg6ciLlUt4DXUbFAGGx9K",
      "432125346-6247381",
      "google-site-verification=jb-qAE0Qy-NAyOuv1frZT1A1UE6gNE955_I3lhjZP_0",
      "canva-site-verification=M-ynsH9PuwqgXIvdn1n6XA",
      "google-site-verification=CmwXiGhZe_wN9v_ACMLi26gPNF8jMSiO7IIm3uJDflU",
      "wiz-domain-verification=22e8ef3cd472ce86a7a48ea0bf2d3113fa543c2d41f969132187ce1c7142466e",
      "facebook-domain-verification=12wxrtyxlslijcmfpit8f0fwtlywlz",
      "v=spf1 include:spf.protection.outlook.com include:_spf.salesforce.com include:_spf.google.com include:spfa.dailymotion.com include:spfb.dailymotion.com include:spfc.dailymotion.com ~all",
      "figma-domain-verification=cbb3b2f479e5448b33c1db6b92c0a5c13113593739aa38b3ab18f4e7dfcad023-1777467509",
      "MS=ms31612776",
      "docusign=c8b32be7-de71-4c64-a061-78cd9ef299ee",
      "atlassian-domain-verification=1fQPUuD1xWMMiqUh4TDo7tO4mPlbE/ptj393wMdMtIRv5UXlZmKDb2cfLlApGCBs",
      "miro-verification=a02c054603f34e1def7bec67636b72d31e230cf4",
      "OSSRH-69635",
      "jamf-site-verification=tyNylgsFuzDaZKhtv2ws8A"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-reports@dailymotion.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.dailymotion.com",
    "issuer": "countryName=AT, organizationName=ZeroSSL GmbH, commonName=ZeroSSL RSA DV SSL CA 2",
    "notBefore": "Jul 27 00:00:00 2026 GMT",
    "notAfter": "Oct 25 23:59:59 2026 GMT",
    "san": [
      "*.dailymotion.com",
      "dailymotion.com"
    ],
    "days_left": 30,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": false,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "195.8.215.136",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: DMS/1.0.42"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": "",
      "error": "ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='dailymotion.com', port=443): Read timed out. (read timeout=8)\"))"
    },
    {
      "origin": "https://sub.dailymotion.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://dailymotion.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 0",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 0",
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
    "/wp-login.php": 0,
    "/phpmyadmin/index.php": 0,
    "/server-status": 301,
    "/api/": 0
  },
  "subdomains": {
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 226.8,
  "rechecked": "2026-09-25 10:43 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
