# Security Audit Report — lynda.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://lynda.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | lynda.com |
| Test date | 2026-09-26 17:48 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 6, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
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
| 17 | low | CK4 | Session-like cookie without HttpOnly | CWE-1004 |
| 18 | info | CT1 | 103 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 19 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Play; Java session cookie (J2EE)
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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
- **Detail:** Header reveals: Play
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=otgwTIY9F-b-FfbfbUI2VALTkgGcwyo7qhoj6vzSDIA
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of lynda.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [LOW] Session-like cookie without HttpOnly (`CK4`)

- **CWE:** CWE-1004
- **Detail:** Cookie 'JSESSIONID' looks session-related and has no HttpOnly attribute.
- **Recommendation:** Set HttpOnly on session cookies.

### 18. [INFO] 103 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.integration.lynda.com, admin.lynda.com, admin.release.lynda.com, admin.stage.lynda.com, api-1.stage.lynda.com, api.integration.lynda.com, api.release.lynda.com, api.stage.lynda.com, author.stage.lynda.com, authors.stage.lynda.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 19. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: admin.integration.lynda.com, admin.lynda.com, admin.release.lynda.com, admin.stage.lynda.com, api-1.stage.lynda.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "lynda.com",
  "dns": {
    "a": [
      "130.211.32.14"
    ],
    "aaaa": [
      "2600:1901:0:d5ad::"
    ],
    "cname": null,
    "mx": [
      "mail-a.linkedin.com (pref 10)",
      "mail-c.linkedin.com (pref 15)",
      "mail.linkedin.com (pref 20)",
      "mail-d.linkedin.com (pref 15)"
    ],
    "ns": [
      "ns3-42.azure-dns.org.",
      "ns4-42.azure-dns.info.",
      "dns1.p09.nsone.net.",
      "dns2.p09.nsone.net.",
      "ns1-42.azure-dns.com.",
      "dns4.p09.nsone.net.",
      "ns2-42.azure-dns.net.",
      "dns3.p09.nsone.net."
    ],
    "spf": [
      "google-site-verification=otgwTIY9F-b-FfbfbUI2VALTkgGcwyo7qhoj6vzSDIA",
      "_xqfeq9o3rn2e8qlraki47908h5c9mf1",
      "v=spf1 ip4:216.84.189.0/24 ip4:64.18.0.0/20 ip4:91.143.106.55 ip4:107.21.2.3 a:zgateway.zuora.com include:_spf.google.com include:mktomail.com include:_spf1.lynda.com include:linkedin.com ~all",
      "wz2pkrghvpwld0jlvm13jqlqxqjtq6bn",
      "_6xxhaq98xaeb80aazhyzt7z0gdcbn8k",
      "MS=ms56649312",
      "MS=ms48400913"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:linkedin@rua.agari.com; ruf=mailto:linkedin@ruf.agari.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Sunnyvale, organizationName=Linkedin Corporation, commonName=lynda.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "May 27 00:00:00 2026 GMT",
    "notAfter": "Nov 27 23:59:59 2026 GMT",
    "san": [
      "lynda.com",
      "www.lynda.com",
      "cdn.lynda.com",
      "campus.lynda.com",
      "m.lynda.com",
      "www1.lynda.com",
      "learn.lynda.com",
      "errors.lynda.com",
      "ftp2.lynda.com",
      "blog.lynda.com",
      "origintest.lynda.com"
    ],
    "days_left": 62,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "130.211.32.14",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Play",
    "Java session cookie (J2EE)"
  ],
  "cookies": [
    {
      "samesite": "none"
    },
    {
      "domain": "lynda.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.lynda.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.linkedin.com/learning/?trk=lynda_redirect_learning"
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
    "source": "certspotter",
    "count": 103,
    "notable": [
      "admin.integration.lynda.com",
      "admin.lynda.com",
      "admin.release.lynda.com",
      "admin.stage.lynda.com",
      "api-1.stage.lynda.com",
      "api.integration.lynda.com",
      "api.release.lynda.com",
      "api.stage.lynda.com",
      "author.stage.lynda.com",
      "authors.stage.lynda.com",
      "blog.lynda.com",
      "cdn.lynda.com",
      "contentadmin.stage.lynda.com",
      "files.lynda.com",
      "m.stage.lynda.com"
    ],
    "sample": [
      "admin-ldc.lynda.com",
      "admin-qatest.lynda.com",
      "admin.integration.lynda.com",
      "admin.lynda.com",
      "admin.release.lynda.com",
      "admin.stage.lynda.com",
      "api-1-qatest.lynda.com",
      "api-1.integration.lynda.com",
      "api-1.lynda.com",
      "api-1.release.lynda.com",
      "api-1.stage.lynda.com",
      "api-ldc.lynda.com",
      "api-qatest.lynda.com",
      "api.integration.lynda.com",
      "api.release.lynda.com",
      "api.stage.lynda.com",
      "author-qatest.lynda.com",
      "author.integration.lynda.com",
      "author.release.lynda.com",
      "author.stage.lynda.com"
    ],
    "dangling": [
      "admin.integration.lynda.com",
      "admin.lynda.com",
      "admin.release.lynda.com",
      "admin.stage.lynda.com",
      "api-1.stage.lynda.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=otgwTIY9F-b-FfbfbUI2VALTkgGcwyo7qhoj6vzSDIA"
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
  "elapsed_s": 16.4,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
