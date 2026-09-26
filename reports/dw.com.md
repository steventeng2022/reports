# Security Audit Report — dw.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dw.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | dw.com |
| Test date | 2026-09-26 14:54 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 4, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | CT1 | 17 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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

### 10. [INFO] 17 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: jobs.dw.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "dw.com",
  "dns": {
    "a": [
      "194.55.26.46",
      "194.55.30.46"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "dw-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "dns4.netcologne.de.",
      "voltaire.dwelle.de.",
      "dns5.netcologne.de.",
      "dns3.netcologne.de."
    ],
    "spf": [
      "teamviewer-sso-verification=57fb36a8398445fc808d31a8bee8edca",
      "jamf-site-verification=VzImhW6bKsbg86C4ZMCWfg",
      "apple-domain-verification=71lMwTH6feCf0VJS",
      "adobe-idp-site-verification=dd7ac996-1443-4180-9755-342404d53a4c",
      "KewQ0sSdpaTF58pY71mtuZuuRhTip0nkIZQXczy8YI3flbo0X0MX2ymCjtQSHysSX/tHB691GLsOAB4ob9g+rA==",
      "v=spf1 ip4:194.55.30.155 ip4:194.55.30.156 ip4:194.55.26.155 ip4:194.55.26.156 ip4:81.209.250.80 ip4:81.209.250.76 ip4:81.209.250.78 ip4:83.133.243.211 ip4:185.17.245.132 ip4:185.17.245.28",
      " include:spf.umantis.com include:spf.de.umantis.com include:spf.protection.outlook.com",
      " include:spf1.checkinserver.com include:spf.vizito.be include:spf.send.business-beat.eu -all",
      "amazonses:NcKjDbDrJqvaflTjJpYU24E8SwJhcD8L4P8f0UYl7rQ=",
      "miro-verification=5b57a1504272050f14683cddfb29af797bfa1133",
      "MS=ms20961559",
      "apple-domain-verification=vBdShnLUGnPMCvIg"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;ruf=mailto:dmarc-report@dw.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=DE, stateOrProvinceName=Nordrhein-Westfalen, localityName=Bonn, organizationName=Deutsche Welle, commonName=*.dw.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=Thawte TLS RSA CA G1",
    "notBefore": "Feb 17 00:00:00 2026 GMT",
    "notAfter": "Mar 20 23:59:59 2027 GMT",
    "san": [
      "*.dw.com",
      "dw.com"
    ],
    "days_left": 175,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "194.55.26.46",
    "open": []
  },
  "https": {
    "status": 301,
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
      "origin": "https://sub.dw.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.dw.com/"
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
    "count": 17,
    "notable": [
      "jobs.dw.com"
    ],
    "sample": [
      "cr.dw.com",
      "design.dw.com",
      "dw.com",
      "go.dw.com",
      "hlsvod.dw.com",
      "innovation.dw.com",
      "jobs.dw.com",
      "llm-hub-dev.dw.com",
      "llm-hub-prod.dw.com",
      "llm-hub.dw.com",
      "mai.dw.com",
      "mimir-poc.dw.com",
      "newsletter-tracking.dw.com",
      "phone-check.dw.com",
      "surveys.dw.com",
      "training.dw.com",
      "tv-download.dw.com"
    ]
  },
  "elapsed_s": 24.1,
  "rechecked": "2026-09-26 16:29 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
