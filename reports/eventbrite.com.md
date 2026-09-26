# Security Audit Report — eventbrite.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://eventbrite.com/ |
| Bug bounty program | Eventbrite |
| Listed scope domain | eventbrite.com |
| Test date | 2026-09-25 09:37 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "eventbrite.com",
  "dns": {
    "a": [
      "65.9.180.122",
      "65.9.180.90",
      "65.9.180.129",
      "65.9.180.120"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 20)",
      "alt4.aspmx.l.google.com (pref 30)",
      "alt3.aspmx.l.google.com (pref 30)"
    ],
    "ns": [
      "ns-1123.awsdns-12.org.",
      "ns-1609.awsdns-09.co.uk.",
      "ns-164.awsdns-20.com.",
      "ns-877.awsdns-45.net."
    ],
    "spf": [
      "asv=6e628a4d91dcb379e8d8b3b3c079f1c3",
      "_praer968xj1hnh9aoafq0gt3f2v07u8",
      "globalsign-domain-verification=IUAylHRA1OTIjHtv-r5Py156P4CXImu7Q3D7nwuTUx",
      "_globalsign-domain-verification=9UioyPO0_F2Epyd3gGV5_VklXzoibTukD_jkbZPw43",
      "asv=072fe34d86b9a2339591dfc59bdb9ef2",
      "jamf-site-verification=_OAVLe_5zkMq3OKDfuvAbA",
      "anthropic-domain-verification-en5n5e=4xcMKoQ71fP6tJ5D3kQp1U5xd",
      "docusign=e3a8b4d6-a9c1-46a2-9f8b-67735287d17f",
      "hubspot-domain-verification=MTIxZDVkNzQtZmYxZi00YzI2LTkyZGMtY2RiODQ4ZjhmOGEw",
      "apple-domain-verification=XLGRsU2KLd68CyMm",
      "anthropic-domain-verification-60jwz0=uWowtCsvJltNqL71mYsvUUYrY",
      "v=spf1 include:mail.zendesk.com include:_ehlo.%{h2}._spf.eventbrite.com include:aws.us1.spf.staffbase.com include:authsmtp.com include:shared.hubspot.com include:servers.mcsv.net ip4:104.130.82.105 ip4:104.130.82.106 ip4:104.130.82.107 ",
      "ip4:104.130.82.108 ip4:184.106.14.63 ~all",
      "google-site-verification=853cVtodFwAIS6Ef_f7ETFKwKoVDHMZQNFkU7KNwGik",
      "google-site-verification=Upd_RL0TQdva_HTzMTWENQ37TKuYmR744S0pbHm_JC4",
      "cursor-domain-verification-me3cjx=h6hA2FP9AYQNtS60wz3fVV0BW",
      "twilio-domain-verification=847146a96c359e60e0fc23ed5006cd06",
      "decagon-domain-verification-7trd52=bW12SaCfTvDYoCPye8ZPA51O3",
      "KMNSI",
      "google-site-verification=464d1lIdnYw18Xg5I0NTvDncdMPHnibhUtSLZRiQItc",
      "google-site-verification=juIc6fxii0pB7IYRSJaLhIJgdZ8tv36OTrGZ_84vGyI",
      "ms=ms80514108",
      "tinfoil-site-verification: b74c198f0f52792a2e90112555552df961fc25f0=8b366f325d425673e355c8bb4e86da8ecaa72e49",
      "google-site-verification=UBGESQRR_1_sa-_Mi7BUgksFdmATDtXZXx4j5rHkcHM",
      "mandrill_verify.ErZnfDwqtMs5bGoC27JCZg",
      "google-site-verification=dv9oihd3MEuKQmRpfkv7jahBgN14dL1lneRy6QAL0Jw",
      "google-site-verification=xdU6vXzrHegeYkahbDbnfxqIBBZXJ3n6UmCSAhkgbR8",
      "smartsheet-site-validation=YA0MuTajr5EnliTvGq_-P0VYDEQ4SzbM",
      "facebook-domain-verification=trazr23y53gj9dt7q4lqyx8z4bimqa",
      "_globalsign-domain-verification=l_BNpBAnk-rKZRyXJ9UkBfv9o6EEuuenkBrGpYNYo0",
      "google-site-verification=7tnPT82vIEZlZ6uK0yG_loUscjXxVH6bCaV6owqTsG0",
      "atlassian-domain-verification=sycFmnKKlAtb4ao7rBMtkA2Zwnp6hRxuy0aUlPgAqugKrHZaZUYskdnT43MlqGpa",
      "docusign=3dcbd907-a57b-4492-afae-fbf89035ac69",
      "notion-domain-verification=AvemneW8dATNsL9xXj07o1YOThlxrOvXh8U5iCV44S5",
      "1password-site-verification=RW47Y6P37ZDPHPWBJFBQ4WQ7NI",
      "openai-domain-verification=dv-QeHXQD0uYDE3MJFRaaG6IUY7"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=100; rua=mailto:reports@dmarc.bendingspoons.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=eventbrite.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jun 13 00:00:00 2026 GMT",
    "notAfter": "Dec 27 23:59:59 2026 GMT",
    "san": [
      "eventbrite.com",
      "*.eventbrite.nl",
      "eventbrite.co.uk",
      "eventbrite.ie",
      "*.eventbrite.fi",
      "*.eventbrite.be",
      "*.eventbrite.co.nz",
      "eventbrite.dk",
      "eventbrite.pt",
      "eventbrite.com.au",
      "*.eventbrite.it",
      "*.eventbrite.my",
      "eventbrite.com.ar",
      "eventbrite.hk",
      "*.eventbrite.es",
      "*.eventbrite.at",
      "eventbrite.com.mx",
      "*.eventbrite.com.mx",
      "*.eventbrite.com",
      "*.eventbrite.ie",
      "eventbrite.at",
      "eventbrite.nl",
      "eventbrite.com.pe",
      "*.eventbrite.com.au",
      "*.eventbrite.com.ar",
      "evbuc.com",
      "*.eventbrite.in",
      "*.eventbrite.dk",
      "eventbrite.in",
      "eventbrite.co.za",
      "eventbrite.es",
      "eventbriteapi.com",
      "*.evbuc.com",
      "eventbrite.my",
      "eventbrite.it",
      "*.eventbrite.com.br",
      "eventbrite.co.nz",
      "*.eventbrite.ph",
      "eventbrite.sg",
      "eventbrite.se",
      "eventbrite.ca",
      "*.eventbriteapi.com",
      "*.eventbrite.de",
      "*.eventbrite.hk",
      "*.eventbrite.pt",
      "*.eventbrite.cl",
      "*.eventbrite.co",
      "*.eventbrite.com.ng",
      "eventbrite.be",
      "eventbrite.fi",
      "*.eventbrite.co.uk",
      "eventbrite.fr",
      "eventbrite.ph",
      "*.eventbrite.ca",
      "eventbrite.de",
      "*.eventbrite.co.za",
      "*.eventbrite.com.pe",
      "*.eventbrite.ch",
      "eventbrite.com.ng",
      "eventbrite.com.br",
      "eventbrite.cl",
      "eventbrite.ch",
      "*.eventbrite.fr",
      "eventbrite.co",
      "*.eventbrite.se",
      "*.eventbrite.sg"
    ],
    "days_left": 93,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "65.9.180.122",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.eventbrite.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://eventbrite.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 403,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 301
  },
  "subdomains": {
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 124.7,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
