# Security Audit Report — tesla.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://tesla.com/ |
| Bug bounty program | Tesla |
| Listed scope domain | tesla.com |
| Test date | 2026-09-25 10:23 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 4, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
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
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=15768000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AkamaiGHost
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
  "domain": "tesla.com",
  "dns": {
    "a": [
      "2.18.49.207",
      "23.40.100.207",
      "2.18.51.207",
      "2.18.54.207",
      "2.18.48.207",
      "23.7.244.207",
      "2.18.50.207",
      "2.18.53.207",
      "2.18.52.207",
      "2.18.55.207"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "tesla-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "edns69.ultradns.com.",
      "a1-12.akam.net.",
      "a9-67.akam.net.",
      "a10-67.akam.net.",
      "a28-65.akam.net.",
      "a7-66.akam.net.",
      "a12-64.akam.net."
    ],
    "spf": [
      "traction-guest=b4f7ad59-bf17-4b3c-8b36-9c2d28f1de32",
      "_w19nckjurfa4aldim48vtbrxsq1phnv",
      "google-site-verification=Y7lbse5bSatjXaqSBOWXjsit4mOp9cQzfLDpnQUSZlg",
      "google-site-verification=Xg2DEUg2oCz1q9RMx8gh2htHK16_GG9cZXY_eyeSf6w",
      "logmein-domain-confirmation=9zxwVn2buGWrLtU24J88",
      "adobe-idp-site-verification=321c026a-3a8c-4206-a1fa-391a59585c54",
      "jamf-site-verification=u4x3LuqSfpoLn5nJ0zMd5g",
      "cloudflare_dashboard_sso=5c0b681b716d2de0666f5a564a4d9c0d",
      "_quuerjb9mywulmdygnzgnt9awyzm15c",
      "zapier-domain-verification-challenge=64e810e8-0fe1-4de0-b104-229592811c5b",
      "docker-verification=74d1ec4e-a7a6-48a7-9568-9bd0faac833f",
      "bugcrowd-verification=40bd5dd89a6e4073ca9bc76feac3a47b",
      "MS=ms22358213",
      "traction-guest=c8bad9fc-4b36-4f6d-944e-783ed41b34b7",
      "domain-verification=0f075f7f33bd0e577c0a56c5bb071f9eedadba45f32da11304913c6afd4b99c7",
      "teamviewer-sso-verification=2fc989f75b19494fab5eb0e2c22dd625",
      "dell-technologies-domain-verification=tesla.com_c363f56d-9650-430a-82d3-04ac2257c64a_1756487968",
      "logmein-verification-code=JFAnsPovogeJ4IeW5MXCU3r0C",
      "T0E0S29854",
      "atlassian-domain-verification=U31RjXDO5NBJROoOVpVEsKJ7daGpXuXPDF8HeqlmvXUKOtTao652TOMtejHrohKB",
      "ms-domain-verification=e335cec9-0ff5-4a54-b8bc-8966a8d146db",
      "adobe-sign-verification=efb2da198047b7a154bd604d2721038b",
      "ms-domain-verification=820e4be7-563e-4f52-b73a-5c9ecdd2fda4",
      "_i88zzpi9e3jr0xglot953efk0ui36y5",
      "v=spf1 ip4:54.240.84.225/32 ip4:54.240.84.226/31 ip4:54.240.84.228/30 ip4:54.240.84.232/29 ip4:54.240.84.240/29 ip4:54.240.84.248/30 ip4:54.240.84.252/32 ip4:44.239.249.139 ip4:52.24.70.112 ip4:34.223.204.78 ip4:213.244.145.203 ip4:213.244.145.219 ip4:213",
      ".244.145.204 ip4:213.244.145.220 ip4:8.47.24.203 ip4:8.47.24.219 ip4:8.47.24.204 ip4:8.47.24.220 ip4:8.45.124.203 ip4:8.45.124.219 ip4:8.45.124.204 ip4:8.45.124.220 ip4:8.21.14.203 ip4:8.21.14.219 ip4:8.21.14.204 ip4:8.21.14.220 ip4:8.21.14.194 ip4:8.21.1",
      "4.211 ip4:212.49.145.0/24 ip4:91.103.52.0/22 ip4:168.245.123.10 ip4:216.81.144.165 ip4:149.72.247.52 ip4:149.72.134.64 ip4:149.72.152.236 ip4:149.72.163.58 ip4:149.72.172.170 ip4:167.89.90.62 ip4:158.228.129.79 ip4:216.81.144.165 ip4:117.50.14.178 ip4:117",
      ".50.35.199 ip4:54.240.42.110 ip4:54.240.42.111 ip4:199.71.239.178 ip4:67.216.183.10 ip4:8.43.178.222 ip4:64.95.144.196 ip4:199.71.239.52 include:u13494342.wl093.sendgrid.net include:spf.protection.outlook.com include:mail.zendesk.com include:_spfsn.teslam",
      "otors.com include:_spf.qualtrics.com include:_spf.ultipro.com include:_spf.psm.knowbe4.com include:spf1.sendcloud.org include:spf2.sendcloud.org -all",
      "_f32sd18rpksw3zh1hgbhaulpv016hoh",
      "google-site-verification=f1YoSQ3nrxPHwlfkwT9Mj_7M_rzQ2RqCPBYHJ9CQNlY  ",
      "_owlpg4menxk5zjwee9xclui989imwbl",
      "cursor-domain-verification-6kgt2s=sxbxrRmk2tNjItWtmh1swmBM0",
      "55zNJIDU0xk94IfGJtL+Hh+wje5JzOS6GY+ntggZF908AUsx0LBKgr+Nln3CgZEUifxSuN09M05jYpdbd6+cpw==",
      "apple-domain-verification=C9J7eOtEbm7Dqr88",
      "onetrust-domain-verification=79a1328740f44bc48dd97ab52c0c3377",
      "onetrust-domain-verification=480735b10e124e23916192d7e4321902",
      "SFMC-qkAv7SvlQaslp7NEALX8t68s_AZWOQB6ThKQS5l5",
      "atlassian-domain-verification=FuJL8qfcWp7BKpnaomRV1Vmay09Vt0rdhikq9Gh/CwPYjsvTIwkrhaVAX1idqUMl",
      "apple-domain-verification=CHZ8RLPKu4dlRxlaNa_nR9oA2MjZ1n2fiE9s0QlbRO8"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:n2ju30bc@ag.dmarcian.com; ruf=mailto:n2ju30bc@fr.dmarcian.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=tesla.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR2",
    "notBefore": "Aug 16 20:25:33 2026 GMT",
    "notAfter": "Nov 14 20:25:32 2026 GMT",
    "san": [
      "tesla.com"
    ],
    "days_left": 50,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "2.18.49.207",
    "open": []
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.tesla.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 403
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 403,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 403,
    "/security.txt": 403,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 57.3,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
