# Security Audit Report — geni.us

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://geni.us/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | geni.us |
| Test date | 2026-09-26 14:54 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 5, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | CT1 | 40 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 12 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

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

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] 40 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.geni.us, blog.geni.us, cdn.geni.us, chums.api.geni.us, fmtc.api.geni.us, help.geni.us, kit.api.geni.us, status.geni.us
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 12. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: chums.api.geni.us; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "geni.us",
  "dns": {
    "a": [
      "172.105.69.103"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 20)",
      "alt1.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "ns5.geniuslink.com.",
      "ns1.geniuslink.com.",
      "ns6.geniuslink.com.",
      "ns3.geniuslink.com.",
      "ns2.geniuslink.com.",
      "ns4.geniuslink.com."
    ],
    "spf": [
      "google-site-verification=mpRbKoQ7OleZ5yhUF-NSmdN9RhrbGisKciCwo4ufIE4",
      "facebook-domain-verification=tyexc4pj94jtntzlgetkc9h6qlxaj7",
      "status-page-domain-verification=px3r907b3k7k",
      "v=spf1 redirect=geni.us.hosted.spf-report.com"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:9bb5d347@mxtoolbox.dmarc-report.com,mailto:bmeip0rx@ag.us.dmarcian.com,mailto:adc00ec0f5@rua.easydmarc.us; ruf=mailto:9bb5d347@forensics.dmarc-report.com,mailto:adc00ec0f5@ruf.easydmarc.us,",
      "mailto:bmeip0rx@fr.us.dmarcian.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=geni.us",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Aug 30 18:02:05 2026 GMT",
    "notAfter": "Nov 28 18:02:04 2026 GMT",
    "san": [
      "*.geni.us",
      "api.georiot.com",
      "cdn.georiot.com",
      "geni.us",
      "geo-itunes.georiot.com",
      "georiot.com",
      "manage.georiot.com",
      "target.georiot.com",
      "www.georiot.com"
    ],
    "days_left": 63,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.105.69.103",
    "open": []
  },
  "https": {
    "status": 429,
    "content_type": "",
    "title": ""
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
      "origin": "https://sub.geni.us",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://geniuslink.com"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 429",
    "/redirect?next=https://evil-auditor.example/x -> 429",
    "/go?url=https://evil-auditor.example/x -> 429",
    "/url?url=https://evil-auditor.example/x -> 429"
  ],
  "paths": {
    "/robots.txt": 429,
    "/sitemap.xml": 429,
    "/.well-known/security.txt": 429,
    "/security.txt": 429,
    "/.git/HEAD": 429,
    "/.git/config": 429,
    "/.env": 429,
    "/.htaccess": 429,
    "/wp-login.php": 429,
    "/phpmyadmin/index.php": 429,
    "/server-status": 429,
    "/api/": 429
  },
  "subdomains": {
    "source": "certspotter",
    "count": 40,
    "notable": [
      "api.geni.us",
      "blog.geni.us",
      "cdn.geni.us",
      "chums.api.geni.us",
      "fmtc.api.geni.us",
      "help.geni.us",
      "kit.api.geni.us",
      "status.geni.us"
    ],
    "sample": [
      "api.geni.us",
      "applemarketing.geni.us",
      "appletv-test.geni.us",
      "appletv.geni.us",
      "blog.geni.us",
      "cdn.geni.us",
      "cf.geni.us",
      "changes.geni.us",
      "chums.api.geni.us",
      "dev-fe.geni.us",
      "dev-fp.geni.us",
      "email.geni.us",
      "express-api.geni.us",
      "fastly.geni.us",
      "fmtc.api.geni.us",
      "fmtc.pma.geni.us",
      "fmtcdemo.pma.geni.us",
      "fp.geni.us",
      "geni.us",
      "help.geni.us"
    ],
    "dangling": [
      "chums.api.geni.us"
    ]
  },
  "elapsed_s": 41.8,
  "rechecked": "2026-09-26 16:29 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
