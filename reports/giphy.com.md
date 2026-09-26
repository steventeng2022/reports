# Security Audit Report — giphy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://giphy.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | giphy.com |
| Test date | 2026-09-26 14:53 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | CT1 | 25 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 11 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443";ma=86400,h3-29=":443";ma=86400,h3-27=":443";ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=15465600 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

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

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [INFO] 25 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.giphy.com, beta.giphy.com, blog.giphy.com, dev.giphy.com, media.giphy.com, status.giphy.com, support.giphy.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 11. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: beta.giphy.com, dev.giphy.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "giphy.com",
  "dns": {
    "a": [
      "151.101.65.55",
      "151.101.193.55",
      "151.101.1.55",
      "151.101.129.55"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)"
    ],
    "ns": [
      "ns-1507.awsdns-60.org.",
      "ns-688.awsdns-22.net.",
      "ns-1872.awsdns-42.co.uk.",
      "ns-8.awsdns-01.com."
    ],
    "spf": [
      "google-site-verification=m6PPLfObSkbjxTzE2TMYuB8ep11oITy1i3O2GqkEQ3A",
      "google-site-verification=wWrXYq5cDpNdZjgDPtJ30mM87mlOArvOCGrkEVndkko",
      "v=spf1 include:sendgrid.net include:_spf.google.com include:_spf.mailgun.org include:_spf.eu.mailgun.org include:servers.mcsv.net exists:%{i}._spf.mta.salesforce.com -all",
      "apple-domain-verification=Fii0eNOZHns9TIAc",
      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1eUbX0WlXcwRefEWDxiZRQI59QABCL+n7ynL/9jASPtr4Nhlqff+AbbImJ7OgWkd6viDUk5RNsafT5dhtjGZTRLooTp2C1UWev9vIM5VBU4MIcW9ZGHuhTNrKPwiLS/TxJAFSE1lGWHmBp0+21XmdMbF/kF8k9WioazM093qmHwIDAQAB",
      "google-site-verification=84mKsZZUB9XYo-Ci3C6ODMErVHAtxe317JWYTbUQjFw",
      "atlassian-domain-verification=2ZiBk8nroSamkeHuamMoEH9zYMfA1R0XO1ZWlq1mnt3E02TV0eaz56swmTVIdMH3",
      "status-page-domain-verification=9qs86qrhsgnd",
      "openai-domain-verification=dv-Sagm5Hc2GH6IccoTx7kqsIPO",
      "TAILSCALE-S8njngbH6JUB9eUyI3hA",
      "00D1U000000q2bj=1TBWj00000001gr"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:add78bd9e2@rua.easydmarc.us,mailto:dmarc@giphy.com; ruf=mailto:dmarc-reports@shutterstock.com; rf=afrf"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.giphy.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2026 Q2",
    "notBefore": "Apr 25 23:03:15 2026 GMT",
    "notAfter": "Nov 10 22:03:15 2026 GMT",
    "san": [
      "*.giphy.com",
      "giphy.com"
    ],
    "days_left": 45,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.65.55",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "GIPHY - Be Animated"
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.giphy.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://giphy.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 403,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 25,
    "notable": [
      "api.giphy.com",
      "beta.giphy.com",
      "blog.giphy.com",
      "dev.giphy.com",
      "media.giphy.com",
      "status.giphy.com",
      "support.giphy.com"
    ],
    "sample": [
      "ads.giphy.com",
      "api.giphy.com",
      "arts.giphy.com",
      "beta.giphy.com",
      "blog.giphy.com",
      "cookies.giphy.com",
      "dev.giphy.com",
      "engineering.giphy.com",
      "eot.giphy.com",
      "giphy-analytics.giphy.com",
      "giphy.com",
      "giphyads.giphy.com",
      "kong.giphy.com",
      "media.giphy.com",
      "media0.giphy.com",
      "media1.giphy.com",
      "media2.giphy.com",
      "media3.giphy.com",
      "media4.giphy.com",
      "pingback.giphy.com"
    ],
    "dangling": [
      "beta.giphy.com",
      "dev.giphy.com"
    ]
  },
  "elapsed_s": 18.6,
  "rechecked": "2026-09-26 14:53 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
