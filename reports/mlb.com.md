# Security Audit Report — mlb.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mlb.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | mlb.com |
| Test date | 2026-09-25 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 4, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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

## Evidence (raw response observations)

```json
{
  "domain": "mlb.com",
  "dns": {
    "a": [
      "34.102.163.158"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mlb-com.mail.protection.outlook.com (pref 1)"
    ],
    "ns": [
      "ns-204.awsdns-25.com.",
      "ns-1370.awsdns-43.org.",
      "ns-976.awsdns-58.net.",
      "ns-cloud-b4.googledomains.com.",
      "ns-1997.awsdns-57.co.uk.",
      "ns-cloud-b3.googledomains.com.",
      "ns-cloud-b2.googledomains.com.",
      "ns-cloud-b1.googledomains.com."
    ],
    "spf": [
      "twilio-domain-verification=5450879a5dddd10b96b14397eb242d58",
      "e2ma-verification=m4j3",
      "paloaltonetworks-site-verification=7be9535bc2affb742cb82ebe821a04088380fb53981671210a413b185923dafc",
      "mgverify=4486080ee27dbe9c532d7c06bd6416c0594bdb2747dc01acfb5e97721389f1c9",
      "onetrust-domain-verification=b65699a512a948ec984777b9ad7d28f7",
      "cloudflare_dashboard_sso=99d69311be411f4639d09940caef8875",
      "mandrill_verify.Ug0KyLxAlKlJFADUoUKazw",
      "yahoo-verification-key=/7YvIV9kTBbJETYphs2ydo2GBj6XuhvO4P1H1M6dh+o=",
      "docusign=dd0cbf68-020f-4af4-9785-638db04566ef",
      "e2ma-verification=0x5bb",
      "6cai8ssdT8bfglT/gt8kwoKyhyAgPcWDuCGhXf6NRtlGOxnCwCVxvE0gV8MARuqkl340xHdWjJtLgFXFk4XOtQ==",
      "facebook-domain-verification=6l9n1mpxxnvj1l19nmitlu3e5t9qgu",
      "google-site-verification=XOnG1KFFRFfMJeUU7-uEnjQPrJ5bgfSKLU3n-ddA5o0",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:mailgun.org ~all",
      "atlassian-domain-verification=g2T53fLDVGlvthuuEp+3tHYaHRCtRg7YE0c6muK0q1eRZToBwzYMwLOUVBbImxpM",
      "asv=f4d8b04afc0fa2a21f4e5156ec6c2789",
      "smartsheet-site-validation=oaC-Jj1jFnvmweM2PoQJUhOQtun7sj3s",
      "anthropic-domain-verification-w0tddh=eUI1DrzYqtNfrirT3GQDfShYK",
      "adobe-idp-site-verification=48421df2-6edd-4d7a-9a50-5d6b7ac37140",
      "onetrust-domain-verification=dd8aecd72e714036a95ea068cfe6f2e7",
      "google-site-verification=xLIe2kvVf_RIlRbMuNhQfxu5QhOj38hG38eCHOVRI-Q",
      "postman-domain-verification=9e8cbf6e58c180aceab032d7f85e916683a73fc5f9dceed2fec8ceba7ca719dddf7b8799b8b78e0153cc9769218729171dd7425c1092c8b14967492e31672762",
      "MS=ms69694204",
      "google-site-verification=ecWDspflVGxmZOFfl5U-feFA50MZguqCygpZH-fHvw0",
      "google-site-verification=ewYCvyU3ZIlPv8GRbEfttW-iXf6Rvo4C1lzUgfi2W4k",
      "openai-domain-verification=dv-D9zatZspLcySUfsBz3ytGnq9",
      "MS=ms85676836",
      "apple-domain-verification=6IYQq9hakr4CM8uN",
      "7zvy2rtgl87v1529vvz467263ttxv00w",
      "cursor-domain-verification-ghqnyw=dHOe7fY7Ygl1Al61QPw1JMNrX",
      "_71zjwgnt0xvgl1emmv7hgs83q8v0jd4"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=mlb.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR3",
    "notBefore": "Sep 12 10:12:02 2026 GMT",
    "notAfter": "Dec 11 11:05:56 2026 GMT",
    "san": [
      "mlb.com"
    ],
    "days_left": 76,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.102.163.158",
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
      "origin": "https://sub.mlb.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.mlb.com/"
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
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 5.2,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
