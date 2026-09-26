# Security Audit Report — coinbase.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://coinbase.com/ |
| Bug bounty program | Coinbase |
| Listed scope domain | coinbase.com |
| Test date | 2026-09-25 09:06 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 2, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
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

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.152.241:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.152.241:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Header reveals: cloudflare
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
  "domain": "coinbase.com",
  "dns": {
    "a": [
      "172.64.152.241",
      "104.18.35.15"
    ],
    "aaaa": [
      "2a06:98c1:310d::6812:230f",
      "2a06:98c1:3102::ac40:98f1"
    ],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "sam.ns.cloudflare.com.",
      "sue.ns.cloudflare.com."
    ],
    "spf": [
      "1password-site-verification=2JYSQ7TWXVDP7DWPHTZRLBRESI",
      "google-site-verification=gwL0hNTFdVrIO_MRAN6m07GJs7aZFGC-XkJcaq8We2s",
      "dropbox-domain-verification=ap29irieph9f",
      "amp-by-sourcegraph-domain-verification-h888ba=g5N2hQggP0wSY4x7gSMgfvyyg",
      "applause-verification:4e8f0335-526a-4a52-8da4-f4ecedc931ef",
      "atlassian-domain-verification=hDuZ4Ho1Rts/J4kaoxR9K2Qnywy2Uo+GV8bDIwXEsE4uovTo0vcL+8AVpI4+3j2V",
      "google-site-verification=qyTrwiATuVJMBGXPOYPOr-NSYW90-idNJU7uTh6-v7Y",
      "giga-domain-verification-956jz3=BliOUPqeH2xWvVWYcEmFCxcwC",
      "docusign=8ace657e-b7bc-4ed2-9cb3-8aa55e7d0597",
      "slack-domain-verification=MlD3gzX7txujPKkmWsULE6w264DyKkTkxbT7nPTd",
      "pylon-domain-verification-sc64gk=B7nJiLr0KeZ0CRv2aVkYTNfjs",
      "mongodb-site-verification=hME8tDWzya9rzZbckAxwpiEiv12KX8Gd",
      "google-site-verification=Mf-1A418PKg0c9t2nAaK4zjWv2A_N8uNGu078EWqCZc",
      "cloudflare_dashboard_sso=2306d311a1bc9c50590c204bf0e527d8",
      "docusign=642eb6c3-8697-4ebd-8a51-a48a05713018",
      "onetrust-domain-verification=f131f1d66b1b445cb8edc36b8edd78e8",
      "facebook-domain-verification=qbphvvib286cbvluswam0qypj99ofm",
      "cursor-domain-verification-tqme34=zHJPl1GeHjzl9e5kOqNqpcepA",
      "jumio-up-idp-domain-verification=59dc5c59-80b3-4697-a85f-e4432d7ba047",
      "google-site-verification=veWhMcRP5-ISDr7tSAI7Mjh9ELqQ7ndOvbHY-xcsl9o",
      "verification_token=KH5SwHZXz5rsFGMABj81aGBnF",
      "verification_token=N5mizUogMNMbNmoFTKuh7KCwg",
      "de7f455f-f2f0-4669-8193-08e31bfab40f",
      "verification_token=fsUf5PQLIwq7nf4HOoQN6ZUCz",
      "apple-domain-verification=7XHeC6zhfdUOulBSjnUyABNhGLx2RMnjebZj2HMPH4w",
      "apple-domain-verification=8HpWlON81jar5xva",
      "TSW_ODg1dGVyYXN3aXRjaA==",
      "v=spf1 include:amazonses.com include:_spf.google.com -all",
      "ahrefs-site-verification_cc6fbe8f6b26b9b07f97892536cda45b7ce7917b040baacf81facc14e820e887",
      "DirectFedAuthUrl=https://coinbase.okta.com/app/coinbase_pwc_1/exk1ke47d0l3gh5gp0x8/sso/saml",
      "plain-domain-verification-5y5tn9=TNqQhlpQ8Bn39aDEnApFcwOxC",
      "google-site-verification=8ww1MRKa0mZPc-WdoZ7YdL64qIE_2bJuIyIagaQqzFo",
      "MS=ms23710130",
      "google-site-verification=F0pv18D2VaKyH77hhpE9OZuDVipTi_YUGqKGzSOUfnQ",
      "miro-verification=790dc2010116c659230c25705d7a5358cd78d99b",
      "tiktok-developers-site-verification=HrFgIdc7KnV2NknroIrwPpiieVmSJjYz",
      "openai-domain-verification=dv-lWXbBpm6xG2ptEFodATJULvV",
      "smartsheet-site-validation=kyRJbpapnk1ExowiffTo0f3Pc-9XKoSh",
      "google-site-verification=5Vrsjlgs1uhwN5AU2Vg1TPuEBasNdhX3CgxtfTdXOQQ",
      "vercel-domain-verification-zvp7d4=jvZ5HXRxnwIhxdzt26biEw6Oh",
      "stripe-verification=f66cbde9148f67d1bb992cfe5ae3fc1efa829c816b726b0bb28ff243325344dc",
      "keybase-site-verification=UlVJ6_FMc2ceBGKC2cjhy8FF1iGw-iuvdc1WzRX7foU"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; adkim=s; aspf=s; fo=1; rua=mailto:jpohmdhp@ag.dmarcian.com; ruf=mailto:jpohmdhp@fr.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=coinbase.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 21 01:34:31 2026 GMT",
    "notAfter": "Dec 20 02:34:19 2026 GMT",
    "san": [
      "coinbase.com",
      "*.cdp.coinbase.com"
    ],
    "days_left": 85,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.64.152.241",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": ".coinbase.com",
      "samesite": "lax"
    },
    {
      "domain": "coinbase.com",
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
      "origin": "https://sub.coinbase.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://coinbase.com/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 134.2,
  "rechecked": "2026-09-25 10:43 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
