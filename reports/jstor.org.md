# Security Audit Report — jstor.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://jstor.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | jstor.org |
| Test date | 2026-09-25 07:58 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

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

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
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
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "jstor.org",
  "dns": {
    "a": [
      "151.101.128.152",
      "151.101.192.152",
      "151.101.0.152",
      "151.101.64.152"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "IthakaHarbors-org.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "usnjpr2ns02.ithaka.org.",
      "usmiaa1ns03.ithaka.org.",
      "usaeaz1ns03.ithaka.org.",
      "usnyny1ns05.ithaka.org.",
      "usnjpr2ns04.ithaka.org.",
      "usnjpr2ns01.ithaka.org.",
      "usaeaz1ns05.ithaka.org."
    ],
    "spf": [
      "u1h2sp5uvkoufuh88hdvhk9orc.",
      "MS=ms59722565",
      "openai-domain-verification=dv-EAO0jUA8iKZCqlqYfddXpA3R",
      "_globalsign-domain-verification=-lBuNJDFRxDkLkNbYOLBU03PlWjnPqAzBPAVUokhAw",
      "sending_domain1053043=a4a2b757167b9ba217895b3e2bb19f3873b9db5b7c0e9b4c6dd2c98c32b93935",
      "v=spf1 mx include:spf.protection.outlook.com include:u1397501.wl.sendgrid.net include:mail.zendesk.com include:aspmx.pardot.com  ~all",
      "google-site-verification=fUzFvqROnu3S1gFEmkwguY42PzRgOFzwg4qQMP24sU4",
      "pardot1053043=4a6c81f133c99f6b859af420931577c383a1b1cd4e153d11ddb1b150a902b382",
      "facebook-domain-verification=t7mhq4udodhlfom0rn909rrhmrcq7f"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:ITI_Win_DMARC@jstor.org; ruf=mailto:ITI_Win_DMARC@jstor.org; fo=0; adkim=r; aspf=r; pct=100; rf=afrf; ri=86400"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=Ithaka Harbors, Inc., commonName=jstor.org",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 OV TLS CA 2026 Q2",
    "notBefore": "Jul 17 20:47:36 2026 GMT",
    "notAfter": "Feb  1 19:47:36 2027 GMT",
    "san": [
      "jstor.org",
      "*.aluka.org",
      "*.apps.prod.jstor.org",
      "*.apps.test.jstor.org",
      "*.artstor.org",
      "*.cdn.aluka.org",
      "*.cdn.jstor.org",
      "*.forum.jstor.org",
      "*.ithaka.org",
      "*.j-img.org",
      "*.jstor.org",
      "*.sharedshelf.artstor.org",
      "*.sharedshelf.stage.artstor.org",
      "*.sr.ithaka.org",
      "*.sscommons.org",
      "*.stage.artstor.org",
      "aluka.org",
      "apps.prod.jstor.org",
      "apps.test.jstor.org",
      "artstor.org",
      "cdn.aluka.org",
      "cdn.jstor.org",
      "ithaka.org",
      "j-img.org",
      "jstor.com",
      "sr.ithaka.org",
      "sscommons.org",
      "www.jstor.com",
      "www.jstor.org",
      "*.constellate.org",
      "jstor.info",
      "www.jstor.info",
      "*.credittransfer.org",
      "*.transferexplorer.org",
      "transferexplorer.org",
      "constellate.org",
      "*.pep.jstor.org",
      "*.test-pep.jstor.org",
      "support.contributors.jstor.org",
      "*.test.jstor.org"
    ],
    "days_left": 129,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.128.152",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.jstor.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.jstor.org/"
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
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 103.6,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
