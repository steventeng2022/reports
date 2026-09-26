# Security Audit Report — faa.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://faa.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | faa.gov |
| Test date | 2026-09-25 09:40 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 1, Low: 6, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | TLS2 | TLS certificate hostname mismatch | CWE-297 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 13 | low | RED7 | HTTPS root redirects to plain HTTP | CWE-319 |
| 14 | low | RED1 | HTTP redirect points to another host over plain HTTP | CWE-319 |
| 15 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [MEDIUM] TLS certificate hostname mismatch (`TLS2`)

- **CWE:** CWE-297
- **Detail:** TLS verification failed: _ssl.c:993: The handshake operation timed out
- **Recommendation:** Serve a certificate whose SAN covers faa.gov.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: BigIP
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
- **Detail:** Header reveals: BigIP
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://faa.gov/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

### 13. [LOW] HTTPS root redirects to plain HTTP (`RED7`)

- **CWE:** CWE-319
- **Detail:** Location: http://www.faa.gov/
- **Context:** https response, /
- **Recommendation:** Redirect to an https:// target.

### 14. [LOW] HTTP redirect points to another host over plain HTTP (`RED1`)

- **CWE:** CWE-319
- **Detail:** Location: http://www.faa.gov/
- **Context:** https response, /
- **Recommendation:** Redirect to the same host over HTTPS.

### 15. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "faa.gov",
  "dns": {
    "a": [
      "155.178.201.85"
    ],
    "aaaa": [
      "2001:19e8:8001:3010::85"
    ],
    "cname": null,
    "mx": [
      "relay3.faa.gov (pref 5)",
      "relay1.faa.gov (pref 5)",
      "relay4.faa.gov (pref 5)",
      "relay2.faa.gov (pref 5)",
      "amcrelay4.faa.gov (pref 5)",
      "amcrelay2.faa.gov (pref 5)",
      "amcrelay1.faa.gov (pref 5)",
      "amcrelay3.faa.gov (pref 5)"
    ],
    "ns": [
      "faa-ct-egm1.faa.gov.",
      "a1-97.akam.net.",
      "a5-65.akam.net.",
      "a14-64.akam.net.",
      "faa-mc-egm1.faa.gov.",
      "a24-64.akam.net.",
      "a11-65.akam.net.",
      "a12-64.akam.net."
    ],
    "spf": [
      "_m0b4vf6qhrh5scrrxosrx9nlq687irj",
      "box-domain-verification=6e6d49a46237d2f704840481289b15d3e7a02a41723fe3cdfd9341b6f52df150",
      "airtable-verification=980f49ddafd00c06f4e37be0a0e74d83",
      "_j0jnoq89nb5odruj97i87etsntvpfoc",
      "_dxoevfz55dgcr8btzsrr2zg588vrpy7",
      "apple-domain-verification=qtgRthDvinDxfuZb",
      "docusign=080db4e4-218c-443b-ad76-1963743f3157",
      "adobe-sign-verification=d9b517c45c4c2b0277445e0d9d7eac344dcb02519394a0ea08faee8c40d85dc3",
      "adobe-idp-site-verification=2d36c88877f2772ad0e628e64e865a3a225928ef49b2967f35ece163e84ae203",
      "zy861l2r0qc6nqjqkwprs8w047f6m44n",
      "google-gws-recovery-domain-verification=61134742",
      "v=spf1 include:faa.gov._nspf.valigov.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.valigov.email ~all",
      "docusign=36a52596-5d8b-4aa8-a3ea-fd823a641d7b",
      "smartsheet-gov-site-validation=mIkWyNAOEJecACv9-NJtfYQNvPNPrAKB",
      "apple-domain-verification=u6VDYAQzYrOfivbe",
      "_mhp0ohi7rqkhwe0s2sd2wz626zbzq50",
      "atlassian-domain-verification=wtYpZOBvqKwb5ZROaraY6fshROjgQ0TOYLAGTZnDsOuoqJCyjOey552col60ndzg"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@valigov.email,mailto:9-AIF-340-DMARC-REPORTS@faa.gov,mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:9-AIF-340-DMARC-REPORTS@faa.gov"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "hostname-mismatch",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "subject": "countryName=US, stateOrProvinceName=District of Columbia, localityName=Washington, organizationName=Federal Aviation Administration, commonName=faa.gov",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "May 11 00:00:00 2026 GMT",
    "notAfter": "Nov 25 23:59:59 2026 GMT",
    "san": [
      "faa.gov"
    ],
    "days_left": 61
  },
  "elapsed_s": 22.9,
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "rechecked": "2026-09-25 07:46 UTC",
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: BigIP"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.faa.gov",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://faa.gov/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  }
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
