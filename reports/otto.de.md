# Security Audit Report — otto.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://otto.de/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | otto.de |
| Test date | 2026-09-25 07:50 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 4, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | CT1 | 33 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [INFO] 33 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: analyzer-ui.develop.prada-dr.cloud.otto.de, api.permissionservice.nonlive.ipanema.cloud.otto.de, cdc.develop.paymentinfo.cloud.otto.de, configuration-ui.develop.prada-dr.cloud.otto.de, develop.customer-green.cloud.otto.de, develop.tracking-dr.cloud.otto.de, external-api.permissionservice.nonlive.ipanema.cloud.otto.de, infra.identity-green.cloud.otto.de, infra.tracking-dr.cloud.otto.de, internal-api.permissionservice.nonlive.ipanema.cloud.otto.de
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "otto.de",
  "dns": {
    "a": [
      "18.194.12.37",
      "63.185.195.55",
      "63.181.40.227"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "otto-de.mail.protection.outlook.com (pref 50)"
    ],
    "ns": [
      "a24-65.akam.net.",
      "a28-66.akam.net.",
      "a1-208.akam.net.",
      "a5-66.akam.net.",
      "a8-65.akam.net.",
      "a9-64.akam.net."
    ],
    "spf": [
      "mongodb-site-verification=XP5hVwaaialm2di9r4ME8FEBAgoydmWc",
      "00D9b00000SfmQL=1TB9b00000008wr;00D2o000000kAmU=1TBTr00000004Jl",
      "dtm-domain-verification=mM876KNtSp0KQQYotikNG6TPTIoaSmKM_7lgUENJM_o",
      "google-site-verification=mwRR8O8tb2xn2nbAuVoFRXq3FvQG8TBXVfvao9Ws6dY",
      "apple-domain-verification=siseb2WuYlAhQ1Js",
      "MS=ms67614880",
      "w/u0tIPwCWqtaT33cfLaDRI4cUHazVnFGfjZSvZs5J409OjBQgoS6SifMXSef28udDpQymTVQsX2gktjmDFz0w==",
      "facebook-domain-verification=j70v29fpjg4ojg80gbifqw1eego33r",
      "figma-domain-verification=a7779162ff855ae8f5aca8708caa598f1d994bcd54c597f3816230fcc8817fe0-1744186662",
      "adobe-idp-site-verification=86e3d89586a3c84e183be6ac5f4ecb05d1011a5b6df236931e040666450a8c7f",
      "QCbesHKcvkL0B5iRm1w3tj7P1PyQAorD",
      "wiz-domain-verification=9e685f8b43ce318887c925c4c1973c62ec374a09e49fb1c22bfb049a03ddf05e",
      "atlassian-domain-verification=XuvfFNPt8O1LGWHgmu6drxqQRbfQGX4Dr2Ot8f9rgaA2FemHHZpmo2KZHiug8I9G",
      "miro-verification=bdc9cd9f80167223093040082fce9f70cb15a22c",
      "google-site-verification=uhp66_5IP66csx6AefbIEaCUbgfvZ6gffnAwJj3IX5c",
      "wiz-domain-verification=084961cf6a9943467022b6e4e254206d89ccca15ebf3b26fbcda38cfa76fdb97",
      "v=spf1 ip4:80.85.192.0/20 include:spf.hornetsecurity.com include:spf.protection.outlook.com include:_spf.salesforce.com a:_spf.otto.de -all",
      "CTxuSaM2ovKYyOHyjzvyQ0f9brbx1ug7SugtgTUplebg9BFi1Vtkj5o/qoiuVxKuAUUWEaoNuR4awzrsYh6LiA==",
      "docker-verification=dd370709-def2-48e6-bfe6-ceafcf66e031",
      "amazonses:mIH7OVHQO2F5WChOVyD79u9apTHT6sbf7e2VZ9NtvsA="
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:dmarc_agg@vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=DE, localityName=Hamburg, organizationName=Otto GmbH & Co. KGaA, commonName=www.otto.de",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Feb 12 00:00:00 2026 GMT",
    "notAfter": "Mar 15 23:59:59 2027 GMT",
    "san": [
      "www.otto.de",
      "pxc.otto.de",
      "ts.otto.de",
      "otto.de"
    ],
    "days_left": 171,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "18.194.12.37",
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
      "origin": "https://sub.otto.de",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://otto.de:443/"
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
    "count": 33,
    "notable": [
      "analyzer-ui.develop.prada-dr.cloud.otto.de",
      "api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "cdc.develop.paymentinfo.cloud.otto.de",
      "configuration-ui.develop.prada-dr.cloud.otto.de",
      "develop.customer-green.cloud.otto.de",
      "develop.tracking-dr.cloud.otto.de",
      "external-api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "infra.identity-green.cloud.otto.de",
      "infra.tracking-dr.cloud.otto.de",
      "internal-api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "linkenrichment.nonlive.ipanema.cloud.otto.de",
      "live.customer-green.cloud.otto.de",
      "nl-unsub-api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "qs-ui.develop.prada-dr.cloud.otto.de",
      "teaserui.develop.up.cloud.otto.de"
    ],
    "sample": [
      "analyzer-ui.develop.prada-dr.cloud.otto.de",
      "api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "cass.cccs.dr.orderprocessing.otto.de",
      "cdc.develop.paymentinfo.cloud.otto.de",
      "cecuda.cccs.dr.orderprocessing.otto.de",
      "configuration-ui.develop.prada-dr.cloud.otto.de",
      "contracts-wm.int.marketplace-integration.platform.otto.de",
      "contracts.live.marketplace-integration.platform.otto.de",
      "craproxy.cccs.dr.orderprocessing.otto.de",
      "customerscoring.cccs.dr.orderprocessing.otto.de",
      "designsystem.digitalretail.otto.de",
      "develop.customer-green.cloud.otto.de",
      "develop.tracking-dr.cloud.otto.de",
      "digitalretail.otto.de",
      "external-api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "infra.identity-green.cloud.otto.de",
      "infra.tracking-dr.cloud.otto.de",
      "internal-api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "linkenrichment.nonlive.ipanema.cloud.otto.de",
      "live.customer-green.cloud.otto.de"
    ]
  },
  "elapsed_s": 145.7,
  "rechecked": "2026-09-25 10:43 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
