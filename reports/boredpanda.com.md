# Security Audit Report — boredpanda.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://boredpanda.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | boredpanda.com |
| Test date | 2026-09-26 01:46 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 6, Info: 8)

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
| 11 | low | RED7 | HTTPS root redirects to plain HTTP | CWE-319 |
| 12 | low | RED1 | HTTP redirect points to another host over plain HTTP | CWE-319 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | info | CT1 | 44 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
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
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [LOW] HTTPS root redirects to plain HTTP (`RED7`)

- **CWE:** CWE-319
- **Detail:** Location: http://www.boredpanda.com/
- **Context:** https response, /
- **Recommendation:** Redirect to an https:// target.

### 12. [LOW] HTTP redirect points to another host over plain HTTP (`RED1`)

- **CWE:** CWE-319
- **Detail:** Location: http://www.boredpanda.com/
- **Context:** https response, /
- **Recommendation:** Redirect to the same host over HTTPS.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [INFO] 44 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: 2.stage.boredpanda.com, api.backbone.boredpanda.com, api.boredpanda.com, api.ideas.boredpanda.com, assets.boredpanda.com, growthbook-api.internal.boredpanda.com, growthbook.internal.boredpanda.com, img.boredpanda.com, img.stage.boredpanda.com, jobs.boredpanda.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "boredpanda.com",
  "dns": {
    "a": [
      "44.216.138.152",
      "98.86.20.9",
      "100.57.211.191",
      "3.212.94.116"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 1)"
    ],
    "ns": [
      "ns-972.awsdns-57.net.",
      "ns-1425.awsdns-50.org.",
      "ns-1985.awsdns-56.co.uk.",
      "ns-173.awsdns-21.com."
    ],
    "spf": [
      "google-site-verification=E-VWzamHJVxn2aKoEbD2dNX18GG_rEuHAJIAcsZ9JQY",
      "google-site-verification=7IVwsmZnsAkCK_7cAFwmFfKsOt-dEkibijx09hJfQhM",
      "v=spf1 a mx include:_spf.mlsend.com include:_spf.google.com include:spf.mailjet.com ~all",
      "google-site-verification=KIIUiAJna3_1-eDilP2A9ENUy2oiWftdyHXyCMhnz3s",
      "brevo-code:59ddf176bd2029a7dea7a297ba5967ef",
      "MS=ms42183495",
      "google-site-verification=XuF5a9eahvWOgNLrh7WkeiFQpnIjdbpEgbWPZ0a1oYY",
      "google-site-verification=MxIMpuiT8s52Vltu5GksnMWb3AmEfjHaawL4ii8SD_Q",
      "google-site-verification=QyUw3s4mkxY3wZMMy4oMT3yHhdCqtiBuusYhmvAdgVM",
      "MS=E04C457D679181C1054598D9F097241502D2B900",
      "anthropic-domain-verification-qp0t5e=qyjWbKPmD6hTz77lb10rBJ2hi",
      "trustpilot-one-time-verification-id=9eb08d90-b03e-4784-821f-4256acbae37d",
      "apple-domain-verification=hops-EdsP_znUZ0tgSnyMFqx9WcQ6J6CLUlLwNJuseY",
      "facebook-domain-verification=fgwdxllanmj6qtcuvmke1si9ec60ia"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:ipm7lrx@ar.glockapps.com,mailto:ipm5swv@ar.glockapps.com,mailto:dmarc_agg@vali.email; ruf=mailto:ipm7lrx@fr.glockapps.com,mailto:ipm5swv@fr.glockapps.com; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=www.boredpanda.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jan 30 00:00:00 2026 GMT",
    "notAfter": "Feb 27 23:59:59 2027 GMT",
    "san": [
      "www.boredpanda.com",
      "www.mirror.boredpanda.com",
      "boredpanda.com",
      "mirror.boredpanda.com"
    ],
    "days_left": 154,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "44.216.138.152",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.boredpanda.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.boredpanda.com:443/"
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
    "count": 44,
    "notable": [
      "2.stage.boredpanda.com",
      "api.backbone.boredpanda.com",
      "api.boredpanda.com",
      "api.ideas.boredpanda.com",
      "assets.boredpanda.com",
      "growthbook-api.internal.boredpanda.com",
      "growthbook.internal.boredpanda.com",
      "img.boredpanda.com",
      "img.stage.boredpanda.com",
      "jobs.boredpanda.com",
      "mail.boredpanda.com",
      "news.boredpanda.com",
      "static.boredpanda.com",
      "static.social-tools.boredpanda.com"
    ],
    "sample": [
      "2.boredpanda.com",
      "2.stage.boredpanda.com",
      "api-read.boredpanda.com",
      "api.backbone.boredpanda.com",
      "api.boredpanda.com",
      "api.ideas.boredpanda.com",
      "app-api.boredpanda.com",
      "assets.boredpanda.com",
      "boredpanda.com",
      "community.boredpanda.com",
      "content.boredpanda.com",
      "gateway.boredpanda.com",
      "growthbook-api.boredpanda.com",
      "growthbook-api.internal.boredpanda.com",
      "growthbook.boredpanda.com",
      "growthbook.internal.boredpanda.com",
      "ideas-tool.boredpanda.com",
      "ideas.boredpanda.com",
      "img.boredpanda.com",
      "img.stage.boredpanda.com"
    ]
  },
  "elapsed_s": 43.1,
  "rechecked": "2026-09-26 03:17 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
