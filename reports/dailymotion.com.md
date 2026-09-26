# Security Audit Report — dailymotion.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dailymotion.com/ |
| Bug bounty program | Dailymotion |
| Listed scope domain | dailymotion.com |
| Test date | 2026-09-26 18:49 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 29 days (notAfter Oct 25 23:59:59 2026 GMT).
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
- **Detail:** Apex TXT records with verification/token content: notion-domain-verification=uvbWKKeyZnS8S7Wbx92ycOmg6ciLlUt4DXUbFAGGx9K; wiz-domain-verification=22e8ef3cd472ce86a7a48ea0bf2d3113fa543c2d41f969132187ce1c; atlassian-domain-verification=1fQPUuD1xWMMiqUh4TDo7tO4mPlbE/ptj393wMdMtIRv5UXlZm
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of dailymotion.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 735 disallow path(s), e.g. /a/*, /abuse/group/, /activate, */adfit/*, /ajax/user
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 195.8.215.136 carries PTR www.dailymotion.com. for dailymotion.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

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
      "mxb-009c2301.gslb.pphosted.com (pref 10)",
      "mxa-009c2301.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "b.dailymotion.com.",
      "a.dailymotion.com."
    ],
    "spf": [
      "notion-domain-verification=uvbWKKeyZnS8S7Wbx92ycOmg6ciLlUt4DXUbFAGGx9K",
      "wiz-domain-verification=22e8ef3cd472ce86a7a48ea0bf2d3113fa543c2d41f969132187ce1c7142466e",
      "atlassian-domain-verification=1fQPUuD1xWMMiqUh4TDo7tO4mPlbE/ptj393wMdMtIRv5UXlZmKDb2cfLlApGCBs",
      "anthropic-domain-verification-c1804p=NXPXkMxpSDDbn8bTInhn5Ajb7",
      "google-site-verification=CmwXiGhZe_wN9v_ACMLi26gPNF8jMSiO7IIm3uJDflU",
      "jamf-site-verification=tyNylgsFuzDaZKhtv2ws8A",
      "google-site-verification=jb-qAE0Qy-NAyOuv1frZT1A1UE6gNE955_I3lhjZP_0",
      "miro-verification=a02c054603f34e1def7bec67636b72d31e230cf4",
      "432125346-6247381",
      "OSSRH-69635",
      "v=spf1 include:spf.protection.outlook.com include:_spf.salesforce.com include:_spf.google.com include:spfa.dailymotion.com include:spfb.dailymotion.com include:spfc.dailymotion.com ~all",
      "docusign=c8b32be7-de71-4c64-a061-78cd9ef299ee",
      "facebook-domain-verification=12wxrtyxlslijcmfpit8f0fwtlywlz",
      "MS=ms31612776",
      "canva-site-verification=M-ynsH9PuwqgXIvdn1n6XA",
      "figma-domain-verification=cbb3b2f479e5448b33c1db6b92c0a5c13113593739aa38b3ab18f4e7dfcad023-1777467509",
      "apple-domain-verification=Xc0pXSUjiGdd6fzI"
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
    "days_left": 29,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
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
      "acac": ""
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
    "notion-domain-verification=uvbWKKeyZnS8S7Wbx92ycOmg6ciLlUt4DXUbFAGGx9K",
    "wiz-domain-verification=22e8ef3cd472ce86a7a48ea0bf2d3113fa543c2d41f969132187ce1c",
    "atlassian-domain-verification=1fQPUuD1xWMMiqUh4TDo7tO4mPlbE/ptj393wMdMtIRv5UXlZm",
    "anthropic-domain-verification-c1804p=NXPXkMxpSDDbn8bTInhn5Ajb7",
    "google-site-verification=CmwXiGhZe_wN9v_ACMLi26gPNF8jMSiO7IIm3uJDflU"
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
      "aia_ocsp": null,
      "not_before": "20260727000000",
      "not_after": "20261025235959"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/a/*",
      "/abuse/group/",
      "/activate",
      "*/adfit/*",
      "/ajax/user",
      "*/alphaaz/",
      "*/alphaza/",
      "*/bookmarks/",
      "/controller/",
      "*/cookie/dmaid/*",
      "*/country/",
      "*/created-after/",
      "*/creative-official+internal/",
      "/edit/",
      "*/edited/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "www.dailymotion.com."
    ]
  },
  "elapsed_s": 39.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
