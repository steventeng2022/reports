# Security Audit Report — coinbase.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://coinbase.com/ |
| Bug bounty program | Coinbase |
| Listed scope domain | coinbase.com |
| Test date | 2026-09-26 18:48 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 3, Info: 12)

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
| 12 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.35.15:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.35.15:8443 succeeded (state-only check, no payload sent).
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

### 12. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.coinbase.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=veWhMcRP5-ISDr7tSAI7Mjh9ELqQ7ndOvbHY-xcsl9o; google-site-verification=gwL0hNTFdVrIO_MRAN6m07GJs7aZFGC-XkJcaq8We2s; dropbox-domain-verification=ap29irieph9f
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of coinbase.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 22 disallow path(s), e.g. /oauth/, /*/oauth/, /signup-interstitial, /*/signup-interstitial, /join/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "coinbase.com",
  "dns": {
    "a": [
      "104.18.35.15",
      "172.64.152.241"
    ],
    "aaaa": [
      "2a06:98c1:3102::ac40:98f1",
      "2a06:98c1:310d::6812:230f"
    ],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "sam.ns.cloudflare.com.",
      "sue.ns.cloudflare.com."
    ],
    "spf": [
      "google-site-verification=veWhMcRP5-ISDr7tSAI7Mjh9ELqQ7ndOvbHY-xcsl9o",
      "google-site-verification=gwL0hNTFdVrIO_MRAN6m07GJs7aZFGC-XkJcaq8We2s",
      "dropbox-domain-verification=ap29irieph9f",
      "google-site-verification=F0pv18D2VaKyH77hhpE9OZuDVipTi_YUGqKGzSOUfnQ",
      "mongodb-site-verification=hME8tDWzya9rzZbckAxwpiEiv12KX8Gd",
      "plain-domain-verification-5y5tn9=TNqQhlpQ8Bn39aDEnApFcwOxC",
      "cursor-domain-verification-tqme34=zHJPl1GeHjzl9e5kOqNqpcepA",
      "de7f455f-f2f0-4669-8193-08e31bfab40f",
      "google-site-verification=Mf-1A418PKg0c9t2nAaK4zjWv2A_N8uNGu078EWqCZc",
      "1password-site-verification=2JYSQ7TWXVDP7DWPHTZRLBRESI",
      "smartsheet-site-validation=kyRJbpapnk1ExowiffTo0f3Pc-9XKoSh",
      "jumio-up-idp-domain-verification=59dc5c59-80b3-4697-a85f-e4432d7ba047",
      "v=spf1 include:amazonses.com include:_spf.google.com -all",
      "google-site-verification=qyTrwiATuVJMBGXPOYPOr-NSYW90-idNJU7uTh6-v7Y",
      "TSW_ODg1dGVyYXN3aXRjaA==",
      "keybase-site-verification=UlVJ6_FMc2ceBGKC2cjhy8FF1iGw-iuvdc1WzRX7foU",
      "verification_token=fsUf5PQLIwq7nf4HOoQN6ZUCz",
      "amp-by-sourcegraph-domain-verification-h888ba=g5N2hQggP0wSY4x7gSMgfvyyg",
      "MS=ms23710130",
      "apple-domain-verification=7XHeC6zhfdUOulBSjnUyABNhGLx2RMnjebZj2HMPH4w",
      "google-site-verification=5Vrsjlgs1uhwN5AU2Vg1TPuEBasNdhX3CgxtfTdXOQQ",
      "DirectFedAuthUrl=https://coinbase.okta.com/app/coinbase_pwc_1/exk1ke47d0l3gh5gp0x8/sso/saml",
      "facebook-domain-verification=qbphvvib286cbvluswam0qypj99ofm",
      "google-site-verification=8ww1MRKa0mZPc-WdoZ7YdL64qIE_2bJuIyIagaQqzFo",
      "miro-verification=790dc2010116c659230c25705d7a5358cd78d99b",
      "applause-verification:4e8f0335-526a-4a52-8da4-f4ecedc931ef",
      "giga-domain-verification-956jz3=BliOUPqeH2xWvVWYcEmFCxcwC",
      "verification_token=N5mizUogMNMbNmoFTKuh7KCwg",
      "stripe-verification=f66cbde9148f67d1bb992cfe5ae3fc1efa829c816b726b0bb28ff243325344dc",
      "docusign=8ace657e-b7bc-4ed2-9cb3-8aa55e7d0597",
      "cloudflare_dashboard_sso=2306d311a1bc9c50590c204bf0e527d8",
      "onetrust-domain-verification=f131f1d66b1b445cb8edc36b8edd78e8",
      "openai-domain-verification=dv-lWXbBpm6xG2ptEFodATJULvV",
      "vercel-domain-verification-zvp7d4=jvZ5HXRxnwIhxdzt26biEw6Oh",
      "slack-domain-verification=MlD3gzX7txujPKkmWsULE6w264DyKkTkxbT7nPTd",
      "ahrefs-site-verification_cc6fbe8f6b26b9b07f97892536cda45b7ce7917b040baacf81facc14e820e887",
      "verification_token=KH5SwHZXz5rsFGMABj81aGBnF",
      "pylon-domain-verification-sc64gk=B7nJiLr0KeZ0CRv2aVkYTNfjs",
      "docusign=642eb6c3-8697-4ebd-8a51-a48a05713018",
      "tiktok-developers-site-verification=HrFgIdc7KnV2NknroIrwPpiieVmSJjYz",
      "atlassian-domain-verification=hDuZ4Ho1Rts/J4kaoxR9K2Qnywy2Uo+GV8bDIwXEsE4uovTo0vcL+8AVpI4+3j2V",
      "apple-domain-verification=8HpWlON81jar5xva"
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
    "days_left": 84,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.35.15",
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=veWhMcRP5-ISDr7tSAI7Mjh9ELqQ7ndOvbHY-xcsl9o",
    "google-site-verification=gwL0hNTFdVrIO_MRAN6m07GJs7aZFGC-XkJcaq8We2s",
    "dropbox-domain-verification=ap29irieph9f",
    "google-site-verification=F0pv18D2VaKyH77hhpE9OZuDVipTi_YUGqKGzSOUfnQ",
    "mongodb-site-verification=hME8tDWzya9rzZbckAxwpiEiv12KX8Gd"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260921013431",
      "not_after": "20261220023419"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/oauth/",
      "/*/oauth/",
      "/signup-interstitial",
      "/*/signup-interstitial",
      "/join/",
      "/*/join/",
      "/spot/*",
      "/*/spot/*",
      "/advanced-trade/spot/",
      "/*/advanced-trade/spot/",
      "/converter/*/*?currencyPage*",
      "/*/converter/*/*?currencyPage*",
      "/price/*?locale*",
      "/*/price/*?locale*",
      "/partner/"
    ]
  },
  "x12": {
    "status": 302
  },
  "elapsed_s": 10.0,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
