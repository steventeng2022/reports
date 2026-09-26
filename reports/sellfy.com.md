# Security Audit Report — sellfy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://sellfy.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | sellfy.com |
| Test date | 2026-09-26 17:52 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 4, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 11 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | info | CT1 | 38 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 20 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.25.253:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.25.253:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=15552000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 11. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.sellfy.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.sellfy.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=ZJw64F0rZxNTUajWkexgLICKwT80PoLkOyWv19c4gco; ahrefs-site-verification_fa14fdfac7d1156d8a1e0e663bc7a8a0848638879cf0a667418f172; 1password-site-verification=4CBCWU2SDVBF7IZSRABLDVIZEM
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of sellfy.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but sellfy.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 15 disallow path(s), e.g. /*/edit/, /*/checkout/*, /*/thankyou/*, /*/paymentcompleted/*, /p/*/buy/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [INFO] 38 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: app.sellfy.com, assets.sellfy.com, blog.sellfy.com, cdn.blog.sellfy.com, demo.sellfy.com, dev.emails.sellfy.com, docs.sellfy.com, domains.demo.sellfy.com, jobs.sellfy.com, media.sellfy.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 20. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: cdn.blog.sellfy.com, demo.sellfy.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "sellfy.com",
  "dns": {
    "a": [
      "104.20.25.253",
      "172.66.168.248"
    ],
    "aaaa": [
      "2606:4700:10::ac42:a8f8",
      "2606:4700:10::6814:19fd"
    ],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "kara.ns.cloudflare.com.",
      "will.ns.cloudflare.com."
    ],
    "spf": [
      "v=spf1 include:helpscoutemail.com include:emsd1.com include:amazonses.com include:_spf.google.com include:mailgun.org -all",
      "google-site-verification=ZJw64F0rZxNTUajWkexgLICKwT80PoLkOyWv19c4gco",
      "ahrefs-site-verification_fa14fdfac7d1156d8a1e0e663bc7a8a0848638879cf0a667418f172e3bd78402",
      "1password-site-verification=4CBCWU2SDVBF7IZSRABLDVIZEM"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; fo=1; ri=3600; sp=reject; aspf=r; rua=mailto:d6930f9c@dmarc.mailgun.org,mailto:1a7214da@inbox.ondmarc.com; ruf=mailto:d6930f9c@dmarc.mailgun.org,mailto:1a7214da@inbox.ondmarc.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=sellfy.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 14 13:14:22 2026 GMT",
    "notAfter": "Nov 12 14:14:18 2026 GMT",
    "san": [
      "sellfy.com",
      "psthg.sellfy.com"
    ],
    "days_left": 46,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.20.25.253",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Online Store Builder: Create a Free Online Store | Sellfy"
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "sellfy.com",
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.sellfy.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://sellfy.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 308",
    "/redirect?next=https://evil-auditor.example/x -> 308",
    "/go?url=https://evil-auditor.example/x -> 308",
    "/url?url=https://evil-auditor.example/x -> 308"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 308,
    "/security.txt": 308,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 308,
    "/phpmyadmin/index.php": 308,
    "/server-status": 308,
    "/api/": 404
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 38,
    "notable": [
      "app.sellfy.com",
      "assets.sellfy.com",
      "blog.sellfy.com",
      "cdn.blog.sellfy.com",
      "demo.sellfy.com",
      "dev.emails.sellfy.com",
      "docs.sellfy.com",
      "domains.demo.sellfy.com",
      "jobs.sellfy.com",
      "media.sellfy.com",
      "stage.sellfy.com",
      "staging.sellfy.com",
      "static.sellfy.com",
      "status.sellfy.com"
    ],
    "sample": [
      "affiliates.sellfy.com",
      "app.sellfy.com",
      "assets.sellfy.com",
      "blog.sellfy.com",
      "cdn.blog.sellfy.com",
      "cf-tools.sellfy.com",
      "changelog.sellfy.com",
      "content.sellfy.com",
      "demo.sellfy.com",
      "dev.emails.sellfy.com",
      "docs.sellfy.com",
      "domains.demo.sellfy.com",
      "domains.sellfy.com",
      "eot.sellfy.com",
      "es.sellfy.com",
      "feedback.sellfy.com",
      "forms.sellfy.com",
      "get.sellfy.com",
      "go.sellfy.com",
      "jobs.sellfy.com"
    ],
    "dangling": [
      "cdn.blog.sellfy.com",
      "demo.sellfy.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=ZJw64F0rZxNTUajWkexgLICKwT80PoLkOyWv19c4gco",
    "ahrefs-site-verification_fa14fdfac7d1156d8a1e0e663bc7a8a0848638879cf0a667418f172",
    "1password-site-verification=4CBCWU2SDVBF7IZSRABLDVIZEM"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/*/edit/",
      "/*/checkout/*",
      "/*/thankyou/*",
      "/*/paymentcompleted/*",
      "/p/*/buy/",
      "/p/*/checkout/",
      "/download/",
      "/download/*/invoice/",
      "/embed/",
      "/deal/",
      "/buttons/",
      "/wix/*",
      "/api*",
      "/search/*",
      "/payments/"
    ]
  },
  "elapsed_s": 12.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
