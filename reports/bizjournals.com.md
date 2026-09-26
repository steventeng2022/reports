# Security Audit Report — bizjournals.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bizjournals.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | bizjournals.com |
| Test date | 2026-09-26 17:40 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 4, Info: 11)

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

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache
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
- **Detail:** Header reveals: Apache
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
- **Detail:** Apex TXT records with verification/token content: anthropic-domain-verification-z8rbfr=rA03Gea7ts0Doz2pIOCL4rKG4; facebook-domain-verification=4bkcthpt3vo2slh46zxfr02h3n3b7v; apple-domain-verification=2xxTxVU2JUjnPwEV
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of bizjournals.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "bizjournals.com",
  "dns": {
    "a": [
      "52.0.29.175",
      "18.206.29.207"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "bizjournals-com.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "ns-1212.awsdns-23.org.",
      "ns-834.awsdns-40.net.",
      "ns-41.awsdns-05.com.",
      "ns-1940.awsdns-50.co.uk."
    ],
    "spf": [
      "anthropic-domain-verification-z8rbfr=rA03Gea7ts0Doz2pIOCL4rKG4",
      "mTOuQnSoBNyuJghOQk+G+G17pJdHY4oOSK66FgpLIQJYT0VH6Ljz8MKbbIkpTP81cbBduvb+nQBNQmsXDAzVFA==",
      "facebook-domain-verification=4bkcthpt3vo2slh46zxfr02h3n3b7v",
      "apple-domain-verification=2xxTxVU2JUjnPwEV",
      "google-site-verification=LevCswd_c1IW1f8mRld4q_d-E4eLJBatxClHcGNeTNs",
      "slack-domain-verification=jfcQJvgKct8FZHxAbGMCwMMs5XSg0AABt1wGwPQZ",
      "canva-site-verification=m8pNzfUCCKpKLpqTjmp6Mg",
      "amazonses:TkdX2fU5+7NqjwIhTKGh4cxDgKG1UzfimAU4+7z9vWI=",
      "logmein-verification-code=e3f76dc8-e880-41c2-9808-25a4ed18f04b",
      "yahoo-verification-key=YbKyySFskGpmC0YtelWQ8EHW/NJD0mxsAiUkAt3m1HQ=",
      "atlassian-domain-verification=sjLsFoaM82p57blkwCOYtnS3pyS0Yh/0FdaZV4PQ1jA/1raOiSGL5wSt/8cbzGH0",
      "google-site-verification=q3vrmfg6zSfgNnkEkz2Vl9bDwAE6khDiIY1NSZWTaH0",
      "globalsign-domain-verification=4F726D3CDF6B074B8A4260CB9F4C377E",
      "v=spf1 a mx ip4:65.213.144.0/24 ip4:54.77.160.217 include:spf.protection.outlook.com include:_spf.salesforce.com include:amazonses.com -all",
      "jamf-site-verification=dje_3yg_ckis5d2BwOuRnw",
      "atlassian-domain-verification=+6pUrCNMUxs+a72CA7DbnV48E2gK47W8AGN/XLQVvDOYxWd7Nz0pKkwro7Vb7GiR",
      "google-site-verification=wcEuZ4UCk4bwVGdq9nr7S1khFSOCR5iGtG-Ig1A4W3c",
      "apple-domain-verification=Z9Ll3GkVj657jbuTXAig5q0mxGEQxSNBwkSpo0NydGc",
      "MS=ms27850487",
      "google-site-verification=lKPntI1ZTAgDVvksd54os6h20CaohO6Nxc4x8hH0BTI",
      "apple-domain-verification=IVCxC0JQ3uDGJMIftpE75X43PjrCTJrNWwe87Xcdof0",
      "WZ66HBVLql6iCPV+U9dCG8glkuZDIPPnHSz6FRnPosNcfYtQgY8CLQ57vjqet+ahOc5ZHSS+OpB/Ym/4VAExXw==",
      "ZOOM_verify_2cUgpojGZjyFOB0WcsL1lN"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:Wv2DBvHlcl@dmarc.inboxmonster.com; ruf=mailto:dmarc@bizjournals.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=bizjournals.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Aug  9 00:00:00 2026 GMT",
    "notAfter": "Feb 22 23:59:59 2027 GMT",
    "san": [
      "bizjournals.com"
    ],
    "days_left": 149,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "52.0.29.175",
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
      "origin": "https://sub.bizjournals.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.bizjournals.com/"
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
    "anthropic-domain-verification-z8rbfr=rA03Gea7ts0Doz2pIOCL4rKG4",
    "facebook-domain-verification=4bkcthpt3vo2slh46zxfr02h3n3b7v",
    "apple-domain-verification=2xxTxVU2JUjnPwEV",
    "google-site-verification=LevCswd_c1IW1f8mRld4q_d-E4eLJBatxClHcGNeTNs",
    "slack-domain-verification=jfcQJvgKct8FZHxAbGMCwMMs5XSg0AABt1wGwPQZ"
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
      "aia_ocsp": null
    }
  },
  "elapsed_s": 30.2,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
