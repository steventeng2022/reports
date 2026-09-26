# Security Audit Report — sellfy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://sellfy.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | sellfy.com |
| Test date | 2026-09-26 16:42 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 3, Info: 11)

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
| 13 | info | CT1 | 38 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 14 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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

### 13. [INFO] 38 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: app.sellfy.com, assets.sellfy.com, blog.sellfy.com, cdn.blog.sellfy.com, demo.sellfy.com, dev.emails.sellfy.com, docs.sellfy.com, domains.demo.sellfy.com, jobs.sellfy.com, media.sellfy.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 14. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

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
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "kara.ns.cloudflare.com.",
      "will.ns.cloudflare.com."
    ],
    "spf": [
      "1password-site-verification=4CBCWU2SDVBF7IZSRABLDVIZEM",
      "v=spf1 include:helpscoutemail.com include:emsd1.com include:amazonses.com include:_spf.google.com include:mailgun.org -all",
      "ahrefs-site-verification_fa14fdfac7d1156d8a1e0e663bc7a8a0848638879cf0a667418f172e3bd78402",
      "google-site-verification=ZJw64F0rZxNTUajWkexgLICKwT80PoLkOyWv19c4gco"
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
  "elapsed_s": 30.3,
  "rechecked": "2026-09-26 16:42 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
