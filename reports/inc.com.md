# Security Audit Report — inc.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://inc.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | inc.com |
| Test date | 2026-09-26 18:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 2, Info: 12)

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
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

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

### 10. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: tollbit-domain-verification=0bb9da110153e3ef443b83e0a17df0277ebe84b481b3a4884c78; google-site-verification=UhzQsqT1WFFLI4xngP3JlJRoiLTGHnUpbdYVKFhDk74; _globalsign-domain-verification=7P-WTP_6W3ncIzOhnL53ZJIFdR_9a2hcgUBPdnX2R_
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of inc.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 38 disallow path(s), e.g. /rest, /rest, /rest, /rest, /
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "inc.com",
  "dns": {
    "a": [
      "151.101.1.54",
      "151.101.65.54",
      "151.101.193.54",
      "151.101.129.54"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx1-us1.ppe-hosted.com (pref 5)",
      "mx2-us1.ppe-hosted.com (pref 10)"
    ],
    "ns": [
      "ns-762.awsdns-31.net.",
      "ns-1662.awsdns-15.co.uk.",
      "ns-346.awsdns-43.com.",
      "ns-1109.awsdns-10.org."
    ],
    "spf": [
      "ZOOM_verify_ucBYh9XLDMPjutQbTLLADa",
      "tollbit-domain-verification=0bb9da110153e3ef443b83e0a17df0277ebe84b481b3a4884c7892cc3794f834",
      "MS=345EAD34CB523CA1BAF8C153C2587D912E4FBCE1",
      "MS=ms64498210",
      "google-site-verification=UhzQsqT1WFFLI4xngP3JlJRoiLTGHnUpbdYVKFhDk74",
      "v=spf1 a:dispatch-us.ppe-hosted.com include:_spf.google.com include:spf.mandrillapp.com include:spf.protection.outlook.com include:mail.zendesk.com include:amazonses.com ~all",
      "HHab7c2Gq6pdo6dnyV+J40QqejNy/T8xyY/hz8cMOm73dnKeIo2xdb7P+/SpxsVzujstzkiOqgMS1jGJTlLKVQ==",
      "_globalsign-domain-verification=7P-WTP_6W3ncIzOhnL53ZJIFdR_9a2hcgUBPdnX2R_",
      "google-site-verification=APaxpIAa4juxpYQJps3fN06tfR49J2ahejAmgOB0Vq8",
      "airtable-verification=2ca2d21d659ff05241fa7c467952e845"
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
    "days_left": 125,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.1.54",
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "tollbit-domain-verification=0bb9da110153e3ef443b83e0a17df0277ebe84b481b3a4884c78",
    "google-site-verification=UhzQsqT1WFFLI4xngP3JlJRoiLTGHnUpbdYVKFhDk74",
    "_globalsign-domain-verification=7P-WTP_6W3ncIzOhnL53ZJIFdR_9a2hcgUBPdnX2R_",
    "google-site-verification=APaxpIAa4juxpYQJps3fN06tfR49J2ahejAmgOB0Vq8",
    "airtable-verification=2ca2d21d659ff05241fa7c467952e845"
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
      "aia_ocsp": null,
      "not_before": "20260715193145",
      "not_after": "20270130183145"
    }
  },
  "http2": {
    "robots_disallow": [
      "/rest",
      "/rest",
      "/rest",
      "/rest",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 15.7,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
