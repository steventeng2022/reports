# Security Audit Report — logitech.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://logitech.com/ |
| Bug bounty program | Logitech |
| Listed scope domain | logitech.com |
| Test date | 2026-09-25 09:57 UTC |
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
- **Detail:** Detected: Server: awselb/2.0
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
- **Detail:** Header reveals: awselb/2.0
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
  "domain": "logitech.com",
  "dns": {
    "a": [
      "3.33.134.116",
      "15.197.157.26"
    ],
    "aaaa": [
      "2600:9000:a715:4dee:d45e:f9bd:7aa6:f56a",
      "2600:9000:a613:2281:6d10:e020:94a9:c625"
    ],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-3.logitech.biz.",
      "ns-2.logitech.com.",
      "ns-1.logitech.com."
    ],
    "spf": [
      "sprout-social-3af93c8b-606d-41aa-a406-d74ebbf4c3ff",
      "dropbox-domain-verification=hwq2jcdw8x2e",
      "atlassian-domain-verification=36rMD0Lad14LyDJ1h86m3vvz70IoE4NlGBQIVNpcq50nPhabI3wJ0RYiSx8Lh5gb",
      "brevo-code:af8945295ad143532a77017f0e34ec18",
      "google-site-verification=wtV3OTVkOcuXsBS2wGLY8ekHymEOksO7qzdC3gXTYtk",
      "facebook-domain-verification=5o5zu88bmhoeu6at7zi31cpa6v2ohi",
      "atlassian-sending-domain-verification=6f94443d-7e50-4c0d-aa98-18883c1f313c",
      "docusign=a0981d32-ab93-4aea-bd63-074847b35ea7",
      "MS=ms37624107",
      "verification_token=gg7Ig8rGwXZnf8KB5zO5PXU79",
      "remarkable-domain-verification=30f96462-62fe-44b7-aa0a-dd41af3b77f6",
      "google-site-verification=eXTK4DovSV0z4ULDUjz2TpIq8gZoHQKAmT112cZ2EF4",
      "google-site-verification=srgm_qMCEej-2s9Vm0kEOOn23zmCBzVFZraEioHFH7o",
      "cursor-domain-verification-dedea7=Ht1ieyMVCO4egVqGx2IiuJoyU",
      "atlassian-domain-verification=WRDFg7vQ8oBuXO0arjtTP2c1eiMt1rl5xX9aqo9/OiqRWjkJxakFVkC3iA7nHpoN",
      "twilio-domain-verification=c324106a4d1b8ca11317499ed11d8181",
      "smartsheet-site-validation=00gHp-KILzZzgbig_6bdpe_TBfOfygnh",
      "MS=ms60342773",
      "apple-domain-verification=BuvO0D6Izr6qJcTM",
      "teamviewer-sso-verification=4733c993b0774f4e88e1f80fd0e428ce",
      "brevo-code:dda1db42545471cfb42a4d7b2ed6c30b",
      "202005060528120ciittu4sdds51am4jnq46267nmi2oyw7ex4x4w7vrew8fh85q",
      "1552c83d-2998-4bf8-8fec-13635be21315",
      "onetrust-domain-verification=2556a4aae1804ed8aa24408789189ac2",
      "google-site-verification=hhpr2B48nkynz2xIR-aYsKVEopC1CXw4yejOFui4XzE",
      "zoom-domain-verification = 40e7be74-ee0b-11ef-9cd2-0242ac120002",
      "shopify-verification-code=GJkIaqt2t0ArMuIvK99fVqL2r91eVg",
      "google-site-verification=C5XQw2J5KPbtStmuVWstr65RWM1OnK751en7znFVvak",
      "freepik-domain-verification=c76f2839abb8e911db2678c9ab93040c",
      "stripe-verification=2276BA764BE86CDB1EDE8F56CBBE2BF28150FB9A98D81D9F07F910C0C21CD100",
      "v=spf1 include:_spf.google.com include:everbridge.net include:mail.zendesk.com include:direct2u.spf.dt.com include:spfa.cpmails.com",
      " ip4:63.150.149.5 ip4:63.150.149.6 ip4:74.118.162.35 ip4:74.118.162.36 ip4:213.165.74.136 ip4:207.211.31.67",
      " ip4:13.110.146.172 ip4:205.139.110.47 ip4:204.77.217.54 ip4:107.23.26.71 ip4:107.23.32.213 ip4:82.195.249.26 ip4:54.251.169.91 ip4:204.77.217.50 ip6:2406:da18:8c8:4e00:c141:5599:cb4:8bd0 ip4:188.40.2.7 ip4:152.160.0.0/16",
      " ip4:37.98.235.2 ip4:199.15.215.48 ip4:54.236.103.127 ip4:208.66.205.16/28 -all",
      "oci-domain-verification=Yg3RbVPioRySsZuLC4koP8tpqyWjJ5zrtD1khwtEk18P",
      "brevo-code:c7b027c990a74ce5f3f8cbd0aae35ba3"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; ruf=mailto:qojun7kz@fr.us.dmarcian.com,mailto:logitechlimited@us.cp-dmarc.com; rua=mailto:logitechlimited@us.cp-dmarc.com,mailto:qojun7kz@ag.us.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=logitech.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Nov 12 00:00:00 2025 GMT",
    "notAfter": "Dec 11 23:59:59 2026 GMT",
    "san": [
      "logitech.com",
      "*.logitechg.com.cn",
      "logitechg.fr",
      "*.logitech.fr",
      "*.logitech.com.cn",
      "logicool.co.jp",
      "*.logitechg.fr",
      "*.logicool.co.jp",
      "logitechg.com",
      "logitech.com.cn",
      "logitechg.com.cn",
      "*.logitech.com",
      "logitech.fr",
      "*.logitechg.com",
      "logitech.ch"
    ],
    "days_left": 77,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "3.33.134.116",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.logitech.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://logitech.com:443/"
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
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 42.9,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
