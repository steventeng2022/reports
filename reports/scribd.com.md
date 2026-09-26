# Security Audit Report — scribd.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://scribd.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | scribd.com |
| Test date | 2026-09-25 10:13 UTC |
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
- **Detail:** Detected: Server: Varnish
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
- **Detail:** Header reveals: Varnish
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
  "domain": "scribd.com",
  "dns": {
    "a": [
      "151.101.194.152",
      "151.101.2.152",
      "151.101.66.152",
      "151.101.130.152"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-00957a01.gslb.pphosted.com (pref 10)",
      "mxb-00957a01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-474.awsdns-59.com.",
      "ns-1449.awsdns-53.org.",
      "ns-630.awsdns-14.net.",
      "ns-2000.awsdns-58.co.uk."
    ],
    "spf": [
      "v=spf1 include:_s00992988.autospf.email include:mailgun.org ~all",
      "anthropic-domain-verification-npy3tx=XrE3YAnz8zeSAImkTUoc1n9eY",
      "ZOOM_verify_qVwNF9TlQp6oTxlx4v4GaA",
      "apple-domain-verification=eURIxHjDOv6GMt8T",
      "spacelift-domain-verification=sjdhfkj3dew",
      "MS=ms82626852",
      "stripe-verification=33707726fea82073ff209aaaeea9f178ca9acdffeb4077b12e4903f92fb9a984",
      "v=spf2.0/mfrom v=spf1 include:_s00992988.autospf.email include:mailgun.org ~all",
      "stripe-verification=07e715389ac4f3434a3223a1e6cd2b7680d193d73de136cde05634188cfdf939",
      "google-site-verification=GggGFvM_T09I1X94IiW555WcOjp5NmcZm-GVh406J44",
      "openai-domain-verification=dv-eOTOMtNqRWMP9Hwl6UWrtzxb",
      "google-site-verification=Ouatu7eN_H_KCzvQGZ-_XLCABWvFM1Ofb4b4hd6ERlg",
      "google-site-verification=Bys0QJsmUcCJ_qCpq6KaSZc2gravmyYLN_EUFENpitg",
      "facebook-domain-verification=svgb7p4y0mkb2o8bjoufff7qvp8f10",
      "github-verification=yRBhv3c3EK2QxM9aeLKy8TT2E4NuSZPuGRSCROOP",
      "atlassian-domain-verification=suO/cHhqQzi2PxMPyb8WEZvFWrAq3fuOv1RfohRyRATHt6P05jFpTBAt9kXV8bVw",
      "segment-site-verification=EJ46G3zd9xfa1md1S3RxDcsZ9olNj7hf",
      "d726596f-b232-406c-8660-a7b13b279ffa",
      "stripe-verification=27d898303b37a8f26350e9d801f6ad3fa671bfd01b2b4f8951e6f1c90ead34e3",
      "mixpanel-domain-verify=aedfc989-2797-4ab3-99e3-ba642eda5fe9",
      "globalsign-domain-verification=Bo6R5k9s2Zwdk5OoeybGk6L2EHx_oV1TqLgGiMR4IQ",
      "mgverify=0ab08701ae09a23d0bc2c38fae847d8f307797fcb1697237391f8128a9640651",
      "cursor-domain-verification-50y66e=D8Uwu2yc3eEBkRMlwCQjSf2gN",
      "openai-domain-verification=dv-JENRwA8a0uUEogtGOcdZfVk8",
      "docusign=fd9b486a-4340-4798-abab-26ce168b0f1b",
      "an2A85lK4eCI+OVQMZRFZ92bkimP99x1WRAzoj7qp/4="
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@dmarc.250ok.net; ruf=mailto:dmarc_fr@dmarc.250ok.net; fo=1; pct=100; rf=afrf"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.scribd.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug 26 16:53:08 2026 GMT",
    "notAfter": "Nov 24 16:53:07 2026 GMT",
    "san": [
      "*.scribd.com",
      "scribd.com"
    ],
    "days_left": 60,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.194.152",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [
    {
      "domain": ".scribd.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.scribd.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://scribd.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 308
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 28.3,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
