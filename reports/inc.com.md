# Security Audit Report — inc.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://inc.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | inc.com |
| Test date | 2026-09-25 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 2, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |

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

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "inc.com",
  "dns": {
    "a": [
      "151.101.129.54",
      "151.101.1.54",
      "151.101.65.54",
      "151.101.193.54"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx1-us1.ppe-hosted.com (pref 5)",
      "mx2-us1.ppe-hosted.com (pref 10)"
    ],
    "ns": [
      "ns-1109.awsdns-10.org.",
      "ns-346.awsdns-43.com.",
      "ns-1662.awsdns-15.co.uk.",
      "ns-762.awsdns-31.net."
    ],
    "spf": [
      "MS=ms64498210",
      "v=spf1 a:dispatch-us.ppe-hosted.com include:_spf.google.com include:spf.mandrillapp.com include:spf.protection.outlook.com include:mail.zendesk.com include:amazonses.com ~all",
      "_globalsign-domain-verification=7P-WTP_6W3ncIzOhnL53ZJIFdR_9a2hcgUBPdnX2R_",
      "google-site-verification=APaxpIAa4juxpYQJps3fN06tfR49J2ahejAmgOB0Vq8",
      "MS=345EAD34CB523CA1BAF8C153C2587D912E4FBCE1",
      "ZOOM_verify_ucBYh9XLDMPjutQbTLLADa",
      "tollbit-domain-verification=0bb9da110153e3ef443b83e0a17df0277ebe84b481b3a4884c7892cc3794f834",
      "google-site-verification=UhzQsqT1WFFLI4xngP3JlJRoiLTGHnUpbdYVKFhDk74",
      "airtable-verification=2ca2d21d659ff05241fa7c467952e845",
      "HHab7c2Gq6pdo6dnyV+J40QqejNy/T8xyY/hz8cMOm73dnKeIo2xdb7P+/SpxsVzujstzkiOqgMS1jGJTlLKVQ=="
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc@inc.com; ruf=mailto:dmarc@inc.com; aspf=s;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.fast-co.net",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2026 Q2",
    "notBefore": "Jul 15 19:31:45 2026 GMT",
    "notAfter": "Jan 30 18:31:45 2027 GMT",
    "san": [
      "*.fast-co.net",
      "*.fastcocreate.com",
      "*.fastcodesign.com",
      "*.fastcoexist.com",
      "*.fastcolabs.com",
      "*.fastcompany.com",
      "*.fastcompany.net",
      "*.inc.com",
      "*.node.inc.com",
      "events.festival.fastcompany.com",
      "events.grill.fastcompany.com",
      "fast-co.net",
      "fastcodesign.com",
      "fastcompany.com",
      "fcimpactcouncil.com",
      "inc.com",
      "one.mansueto.com",
      "static.mvdigitalmedia.com",
      "www.fcimpactcouncil.com",
      "www.mansueto.com",
      "mansueto.com",
      "*.dev.inc.com"
    ],
    "days_left": 127,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.129.54",
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
      "origin": "https://sub.inc.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.inc.com/"
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 11.1,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
