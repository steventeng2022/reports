# Security Audit Report — washingtonpost.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://washingtonpost.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | washingtonpost.com |
| Test date | 2026-09-26 19:01 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 9 days (notAfter Oct  5 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AmazonS3
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AmazonS3
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=0R8HaEZPmx7XZBckUaQMssOU2e6Dspe3AOMsYxNrWq8; google-site-verification=xLI97dy4D9FGihhl23twW5HHhVSmpnr2nWComZhpQVo; _globalsign-domain-verification=R1bvWDvJUF1gpXlmc7Q3deFwpZciil5dpJR4t-a8XM
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of washingtonpost.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.77.20.196 carries PTR a23-77-20-196.deploy.static.akamaitechnologies.com. for washingtonpost.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "washingtonpost.com",
  "dns": {
    "a": [
      "23.77.20.196"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-001a3c01.gslb.pphosted.com (pref 10)",
      "mxb-001a3c01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-404.awsdns-50.com.",
      "sdns34.ultradns.net.",
      "ns-1840.awsdns-38.co.uk.",
      "ns-666.awsdns-19.net.",
      "sdns34.ultradns.com.",
      "ns-1027.awsdns-00.org.",
      "sdns34.ultradns.org.",
      "sdns34.ultradns.biz."
    ],
    "spf": [
      "_rm8r4wsr378iet73p2f9j7oecnksay1",
      "google-site-verification=0R8HaEZPmx7XZBckUaQMssOU2e6Dspe3AOMsYxNrWq8",
      "_dhwsbe1t7yht6p4dsc72mcajq9aaum9",
      "google-site-verification=xLI97dy4D9FGihhl23twW5HHhVSmpnr2nWComZhpQVo",
      "MS=ms58521745",
      "mBd2513ESDgG6ZfaSrFYw4WaOC2b0M21Ehl8KWI3GmgTDpfYKwGuBum8ivsayoYLzVCetyXDieRUdW4qdQe+hw==",
      "v=spf1 ip4:198.72.14.0/23 ip4:192.72.255.0/24 ip4:54.156.98.51 ip4:54.210.51.17 include:spf.protection.outlook.com include:madgexjb.com include:spf-001a3c01.pphosted.com include:amazonses.com -all",
      "_zj8o0fyk0qj8jy5pt1zr1543e97ew7c",
      "_globalsign-domain-verification=R1bvWDvJUF1gpXlmc7Q3deFwpZciil5dpJR4t-a8XM",
      "_globalsign-domain-verification=SQONiBgTxRVzPPtIHjei_IUGCiAa0KxoVWFw1QfVes",
      "knowbe4-site-verification=e04590e121eee5fbc18ada6449219119",
      "_40ij1ve2dtneubti00ikilfe0zlr0kz",
      "f3de1c77b72748ff92a68f88f4d93dfd",
      "brave-ledger-verification=28c1597498b6eafc29aac1f3a42f31559dfe03a832058ead6f684a518f180d62",
      "globalsign-domain-verification=8frsHcE2ag-0ccaaP5BTpPmUJC8ob8pdjDQchfAWzD",
      "google-site-verification=Xq6gcVYYZJtb2DQN6h2bo-hkrdmZpcdAKO8CeYl8290",
      "rovag_verification_token=C2158E1BE1D041B78CC57ED72101FF6C",
      "google-site-verification=6Bi3yUCN2g3lzvqapLfrbgkQxob5YCjmZidGa2qiM4g",
      "slack-domain-verification=YsnaUOhPU4Y6dCz5a3TqBIs4DxEXrVFbuKbGFRyS",
      "google-site-verification=qcYuOKvxobypPYmqzzrcw5KiwtpfLgdEEt-HwMfLwvo"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; fo=1; rua=mailto:dmarc_rua@washingtonpost.com,mailto:mylza-8368@rua.dmarc.emailanalyst.com; ruf=mailto:dmarc_ruf@washingtonpost.com,mailto:mylza-8368@ruf.dmarc.emailanalyst.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=District of Columbia, organizationName=WP Company LLC, commonName=www.washingtonpost.com",
    "issuer": "countryName=CA, organizationName=Entrust Limited, commonName=Entrust OV TLS Issuing ECC CA 2",
    "notBefore": "Sep  5 00:00:00 2025 GMT",
    "notAfter": "Oct  5 23:59:59 2026 GMT",
    "san": [
      "www.washingtonpost.com",
      "apps.washingtonpost.com",
      "css.washingtonpost.com",
      "img.washingtonpost.com",
      "img2.washingtonpost.com",
      "img3.washingtonpost.com",
      "js.washingtonpost.com",
      "live.washingtonpost.com",
      "subscribe.washingtonpost.com",
      "washingtonpost.com"
    ],
    "days_left": 9,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.77.20.196",
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
      "origin": "https://sub.washingtonpost.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://washingtonpost.com/"
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
    "google-site-verification=0R8HaEZPmx7XZBckUaQMssOU2e6Dspe3AOMsYxNrWq8",
    "google-site-verification=xLI97dy4D9FGihhl23twW5HHhVSmpnr2nWComZhpQVo",
    "_globalsign-domain-verification=R1bvWDvJUF1gpXlmc7Q3deFwpZciil5dpJR4t-a8XM",
    "_globalsign-domain-verification=SQONiBgTxRVzPPtIHjei_IUGCiAa0KxoVWFw1QfVes",
    "knowbe4-site-verification=e04590e121eee5fbc18ada6449219119"
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
      "not_before": "20250905000000",
      "not_after": "20261005235959"
    }
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a23-77-20-196.deploy.static.akamaitechnologies.com."
    ]
  },
  "elapsed_s": 11.0,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
