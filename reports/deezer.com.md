# Security Audit Report — deezer.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://deezer.com/ |
| Bug bounty program | Deezer |
| Listed scope domain | deezer.com |
| Test date | 2026-09-25 09:13 UTC |
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
- **Detail:** Detected: Server: AmazonS3
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
- **Detail:** Header reveals: AmazonS3
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
  "domain": "deezer.com",
  "dns": {
    "a": [
      "3.169.55.83",
      "3.169.55.41",
      "3.169.55.75",
      "3.169.55.100"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx5.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx4.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)"
    ],
    "ns": [
      "ns-340.awsdns-42.com.",
      "ns-1072.awsdns-06.org.",
      "ns-672.awsdns-20.net.",
      "ns-1935.awsdns-49.co.uk."
    ],
    "spf": [
      "miro-verification=dfdce60c3dafe475e66cee1a7dff403050e298a9",
      "MS=ms80038696",
      "teamviewer-sso-verification=255ec7551d7b4b16bfc94d0cba632b63",
      "docusign=8d8c13b3-cb80-43af-a6f3-0036bba8d3fc",
      "tiktok-developers-site-verification=fsHQ2q4rKdukpTPlO15oSq88WsUbzChs",
      "wsbvv2s5vf",
      "facebook-domain-verification=wbu2pxqkdmso2hjz7j14fm2hoccy4z",
      "tiktok-developers-site-verification=biDigQ8eMAwiHueSlRfgZYYDQnasm3L2",
      "jamf-site-verification=KLk9LYux1EXjBffu88rVgg",
      "docusign=842e27e7-d700-4873-af3e-0cee181088e5",
      "anthropic-domain-verification-2kxj5s=ldg3Froq5PB3Ue61ZLWcJ120B",
      "brevo-code:fa2e70dc2bb0553ba7f879cdb321c3f0",
      "docker-verification=2fcbee18-9629-4252-b876-b5f09e7f0d52",
      "google-site-verification=od_WkSXO534wNFRABA-6zoxUIVwn60Md6SlU2i5i8iE",
      "google-site-verification=F8ZbIRsZzJL9xffCHf3E56G59z6HjD2CP6I1SRSDP68",
      "google-site-verification=vvyvPgv8IufaTIaccQQlinaL8TQ85_PHDAfcZWtE6O0",
      "atlassian-domain-verification=OKs3QGwhDbZrt7WH4gOo+3G6aSPoFiiO04wvktNpPRFGSzbDMhOz5OKfZMCP+F7Q",
      "browserstack-domain-verification=79af734f-e88b-487f-9191-55c52b27be0b",
      "gradle-verification=F2ED2BTRLBH4T55MB7BLMAHMU3PKH",
      "v=spf1 include:_spf.google.com include:sendgrid.net include:mail.zendesk.com include:servers.mcsv.net ip4:78.40.120.128/26 ip4:78.40.121.0/24 ip4:78.40.123.0/24 ip4:78.40.120.244 ip4:185.159.104.113 ip4:35.241.138.172 -all",
      "apple-domain-verification=P57n1OdYT_c47nnR4KwTymOZrOA0cl32GWqj5pkCGQ0",
      "teamviewer-sso-verification=f9da86a27d794c74b772287a9d5787c2",
      "TAILSCALE-35IXkmM36zZhS07BnS3k",
      "bvAlPqTZ=c6edbdd62238ef342b47a23d07284dad",
      "segment-site-verification=GlpHielfWK2mAxw280lnbJndwol19aGH",
      "google-site-verification=7I-SYis8ZeMmOpyppnK8xwO0zl0svUEAhj8Z2Y9PFcI",
      "yandex-verification: ecd5587d4fbf1dc6",
      "bitrise-verification=07f1c1d2f9ad3bc9-LO62dmQufLLX"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_report@deezer.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=FR, localityName=Paris, organizationName=Deezer SA, commonName=*.deezer.com",
    "issuer": "countryName=FR, organizationName=Gandi SAS, commonName=GandiCert",
    "notBefore": "Jul 16 00:00:00 2026 GMT",
    "notAfter": "Jan 30 23:59:59 2027 GMT",
    "san": [
      "*.deezer.com",
      "deezer.com"
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
    "ip": "3.169.55.83",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AmazonS3"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.deezer.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://deezer.com/"
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
  "elapsed_s": 105.5,
  "rechecked": "2026-09-25 10:43 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
