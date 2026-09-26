# Security Audit Report — xing.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://xing.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | xing.com |
| Test date | 2026-09-26 14:56 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 3, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
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
- **Detail:** Detected: Server: CloudFront
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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
- **Detail:** Header reveals: CloudFront
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
  "domain": "xing.com",
  "dns": {
    "a": [
      "18.154.144.107",
      "18.154.144.64",
      "18.154.144.42",
      "18.154.144.78"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "xing-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns-1321.awsdns-37.org.",
      "ns-291.awsdns-36.com.",
      "ns-633.awsdns-15.net.",
      "ns-1690.awsdns-19.co.uk."
    ],
    "spf": [
      "teamviewer-sso-verification=54188f7fff354a9b92f7652fd3937fb0",
      "miro-verification=3969bd74d34f4d6e10fb42f5233014d2d3dd4f9c",
      "docusign=73ffe7e4-a802-458a-bad3-3afefc637792",
      "astro-domain-verification=clyhbm3ib0dq801kip93vxw0t",
      "segment-site-verification=3fA98vkzGDmgoJbj3AG2CJvr8Z9mSQpx",
      "figma-domain-verification=021dc2f32684e858eaf9842b7206f9197bbdffa76c83ac711b16ba9702aeca5c-1782465718",
      "paloaltonetworks-site-verification=93e36781f48dc570d80205f59263b53045f9a982b7fcc747a23849d162298d7f",
      "google-site-verification=UORS-nc4KF2CsNXjoZmD3hLN9gvo3xdmmRXP2UE0N2Y",
      "v=spf1 mx include:_netblocks.mail.xing.com include:_spf.zimpel.de include:_spf.salesforce.com include:_spf.abiliware.de ?include:servers.mcsv.net include:spf.protection.outlook.com include:mail.zendesk.com ~all",
      "facebook-domain-verification=xxd0q3s7lv62wywvvpver0e8j1j1vw",
      "google-site-verification=1CoJURTg2aHLa8bvDoNt_dDrLNmVPE93-cjaxYitSo8",
      "docker-verification=7d460483-f122-4277-b449-0a3a3fe26190",
      "google-site-verification=Qb3_TK55U83JNTsumhQ_7culHoFKMU2dcpvVvfl5h-k",
      "Ml9vw8Cm/Ig/xpmhhDfS9TEjuzw=",
      "openai-domain-verification=dv-JfWX8IbG0n87GNHoDQvLlbeM",
      "_oqnb58q3pbnwofdf7gr0jeab8ik8xs6",
      "mongodb-site-verification=P5bGlH3I0KYBkV7Lk3ZQPkLsXxb3QN4R",
      "ZOOM_verify_av-wjAz-T62Xdl1pMRBySA",
      "google-site-verification=Flhe3fswMbbqS2VGEy2ODM-1P_PE_Z5l2u5zZZq5UR4",
      "google-site-verification=UqxFvQ_ikK9hga0Qm1unOA9HbMWTTlJ_TTVxRTu9z04",
      "MS=ms45637936",
      "atlassian-domain-verification=jQie6vPSfhfQ4wsCwYZtuCQTWC7PhDbv9HmrAzbRc6skBWWB/TfL8TpiAqozsb8N",
      "TTmNrvKCKyVmW6wxgBUHPZ3Tv4VvPaUslML0MaJAYdnySEHpD7OX4QTOPBLdgFlKfIL59yXY3x6lm8iIyqWwhw==",
      "google-site-verification=whYQbqxkVsb_xI5XKG3U8CQG2Vn75Nhx5HyTxo30gHA",
      "MS=ms63761438",
      "google-site-verification=jC5_MqgVlYS7He0-uldAaB4z1uYxuZUKL_bTHaIYn-0",
      "zoom-domain-verification=5adddeb4-2a0b-4bf0-8eaf-82bc5e2c49d8"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:7675016f@in.mailhardener.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=redirect.xing.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "May  6 00:00:00 2026 GMT",
    "notAfter": "Nov 19 23:59:59 2026 GMT",
    "san": [
      "redirect.xing.com",
      "www.advertising-news.xing.com",
      "*.xingmodules.com",
      "*.openbc.de",
      "preview.api.whatsbroadcast.xing.com",
      "*.xing.de",
      "openbc.de",
      "www.bewerbung.com",
      "www.gehaltsindex.com",
      "*.whatsapp.xing.com",
      "*.xing.com",
      "xing.com",
      "*.coach.xing.com",
      "*.contaxt.de",
      "xing.de",
      "mail.new-work.se",
      "nwse.io",
      "contaxt.de",
      "preview.api.whatsapp.xing.com",
      "*.xing-video.com",
      "recruiting.xing.de",
      "xing.at",
      "*.xing.ch",
      "xingmodules.com",
      "gehaltsindex.com",
      "email.xing.com",
      "*.xn--jobbrse-d1a.com",
      "mail.xing.com",
      "lebenslauf.xn--jobbrse-d1a.com",
      "*.xing.at",
      "xing.io",
      "*.preview.xing.com",
      "xing.ch"
    ],
    "days_left": 54,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "18.154.144.107",
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
      "origin": "https://sub.xing.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://xing.com/"
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
  "elapsed_s": 16.0,
  "rechecked": "2026-09-26 14:53 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
