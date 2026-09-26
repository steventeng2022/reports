# Security Audit Report — fastcompany.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://fastcompany.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | fastcompany.com |
| Test date | 2026-09-26 01:46 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 2, Info: 8)

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
| 10 | info | CT1 | 25 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 10. [INFO] 25 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: auth.fastcompany.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "fastcompany.com",
  "dns": {
    "a": [
      "151.101.129.54",
      "151.101.1.54",
      "151.101.193.54",
      "151.101.65.54"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx2-us1.ppe-hosted.com (pref 10)",
      "mx1-us1.ppe-hosted.com (pref 5)"
    ],
    "ns": [
      "ns-715.awsdns-25.net.",
      "ns-1872.awsdns-42.co.uk.",
      "ns-1515.awsdns-61.org.",
      "ns-27.awsdns-03.com."
    ],
    "spf": [
      "YixrMKRsWOSKfzWgsRRi6NVmxyB4qG17n1iLIxsXxfXzkNFJKBVZXwdtDiU+ZorIZaJZCL/qpzsHemJdhnHfSw==",
      "_globalsign-domain-verification=UNpHzsP3DfgbAxW7_LaHmV-0basWFjytZ3uVL4DUzq",
      "v=spf1 a:dispatch-us.ppe-hosted.com include:_spf.google.com include:spf.mandrillapp.com include:amazonses.com include:spf.protection.outlook.com include:mail.zendesk.com ~all",
      "MS=ms42877241",
      "ca3-05cc9f378ce24610b09ea1bd36527e63",
      "ca3-e2ea934ff9d1486f9910f9c81761fa99 MS=EA6BD12E4042FBE98C6039D238059CE6AE1E347F",
      "buu/MrJiTMBBRF3W3ASumwqjDif644jK3TX5YPk+D5g=",
      "tollbit-domain-verification=96220e3137d5f1dc634856c5e2b7a7ba5f57096a7179bf1fdaa43239646c5108",
      "_globalsign-domain-verification=2wRqY6IrIINLY7B8Qcp-qur9HsiRTO04g4gwsMmFy3",
      "ZOOM_verify_3AkoDfohygJsFa5Q70IqZB",
      "google-site-verification=eO1qsJOo2gALpVdcso2IuN6exMycZNqDOO1XpeqTC_A",
      "_globalsign-domain-verification=3Z8bdt8iCWVQuFZDQkoKYwCoWBX6gyXdBAZWw1GzmI",
      "Fastly-322681-041220-2816749",
      "google-site-verification=PY9DET9Or1b_mkw2Xkgs3TBQaPEHmumzBTOk3_QaZ18",
      "_globalsign-domain-verification=vgLXYEFUoOerT8uIZkhvA3Un5juG_KyzM_4G3EFw0_",
      "_globalsign-domain-verification=klUJkI4MZw-0elRtIBbVGs7d-e1CPM16mbnrVrKORw",
      "google-site-verification=W3-NcdnZXk2Yl4BinFIa3fKWuwJXgC4x-7a7LuiRLHI"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc@fastcompany.com; ruf=mailto:dmarc@fastcompany.com; aspf=s;"
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
    "days_left": 126,
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
      "origin": "https://sub.fastcompany.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.fastcompany.com/"
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
    "count": 25,
    "notable": [
      "auth.fastcompany.com"
    ],
    "sample": [
      "apply.fastcompany.com",
      "auth.fastcompany.com",
      "board-dev.fastcompany.com",
      "board-stg.fastcompany.com",
      "board.fastcompany.com",
      "c783.fastcompany.com",
      "events.fastcompany.com",
      "events.festival.fastcompany.com",
      "events.grill.fastcompany.com",
      "executive-board.fastcompany.com",
      "fastcompany.com",
      "fc-resources.fastcompany.com",
      "go.fastcompany.com",
      "gtm.fastcompany.com",
      "kudos.fastcompany.com",
      "magazine.fastcompany.com",
      "mediakit.fastcompany.com",
      "portfolio.fastcompany.com",
      "register.fastcompany.com",
      "social.fastcompany.com"
    ]
  },
  "elapsed_s": 10.5,
  "rechecked": "2026-09-26 03:17 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
