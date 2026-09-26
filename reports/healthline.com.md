# Security Audit Report — healthline.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://healthline.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | healthline.com |
| Test date | 2026-09-26 17:46 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | SEC2 | security.txt published without a contact address | CWE-1038 |
| 18 | info | CT1 | 39 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: facebook-domain-verification=jj8ocu40cbv4gwsxk5zu85eu8is5l2; adobe-idp-site-verification=b6e27597198dfc9921fbe2ad78e9a76012bb17d0ddb65389e600; google-site-verification=10MtyW5tixgJ1zJl41PFoXGHoCT4rEXnxSDi7c9O2xc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of healthline.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 201 disallow path(s), e.g. /bmajax/, /v2/, /vp/, /corporate/, /health/mirgraine-headaches
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] security.txt published without a contact address (`SEC2`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt returns 200 but contains no mailto:/URL contact.
- **Recommendation:** Add a Contact: field per RFC 9116.

### 18. [INFO] 39 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: shop.healthline.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "healthline.com",
  "dns": {
    "a": [
      "18.164.174.74",
      "18.164.174.14",
      "18.164.174.50",
      "18.164.174.117"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "healthline-com.mail.protection.outlook.com (pref 100)"
    ],
    "ns": [
      "ns-1870.awsdns-41.co.uk.",
      "ns-1494.awsdns-58.org.",
      "ns-397.awsdns-49.com.",
      "ns-532.awsdns-02.net."
    ],
    "spf": [
      "facebook-domain-verification=jj8ocu40cbv4gwsxk5zu85eu8is5l2",
      "adobe-idp-site-verification=b6e27597198dfc9921fbe2ad78e9a76012bb17d0ddb65389e600ecb80de9a555",
      "google-site-verification=10MtyW5tixgJ1zJl41PFoXGHoCT4rEXnxSDi7c9O2xc",
      "google-site-verification=9rByw_q31RzBqs4AA7KUd5DVRtwqu7JaBKtCzREyQ88",
      "fastly-domain-delegation-xn2ic934nfks9dmh043n-534657-02122020",
      "_globalsign-domain-verification=gxDZTHFxmg56fm5vMzUelQcu7UZSnIYHxvoZHAUJYR",
      "_dd6n4s3qhakzb1w9gatf5v5j603qtrx",
      "knowbe4-site-verification=f250b2a70f1bef3a0d3e9e990a25ada0",
      "tollbit-domain-verification=a3c9d22f8e58d1566203122a0e150d927c4c2be942f5fa821f6827cce35b30bc",
      "google-site-verification=HnXFyiSqHNyWCgiGoM5SDWyFcL2ECFWGT0WuHQpAEjI",
      "miro-verification=77455fa727c44a16a04b03e516d6d231cf531916",
      "google-site-verification=qgu4DwxU6jWFVWU3N-2QvWfPYx_TW2sUs27AInNR3wc",
      "MS=ms30320707",
      "prodpad-domain-verification=kIddY6Z63lgRnBLPBKbhQR7HTDwEqC4YvRcqxEXpvqs=",
      "atlassian-domain-verification=bN75F1xIc011Uy6OcB2ErAcqhgLp9gCDQPDRMQr3oPs4AI376WBjcjAG9MkOsNsK",
      "google-site-verification=4TkRPpTNSxxyr6D_knbvmMlsg3bP2l5x0dlg1SYcHM4",
      "google-site-verification=ZkH-iBG2Ktb5cq30xfZBj55gcoR83zyCyWA1v6SqekM",
      "zapier-domain-verification-challenge=e1e58f83-f475-4bea-9a2d-d7fbdfd82352",
      "_58dyqoowvb8lchukwierwtioc1bk6ba",
      "wiz-domain-verification=44d891959955eb64b1b2877c45e2a56cac26905d45f3a7fa090f4a05612b0a30",
      "ZOOM_verify_pBzHNZvUTQq-qLCjv-gnSA",
      "MS=ms47231924",
      "google-site-verification=g-iVuoVfzey1Z8og4DqMnL73y1J-STWZbTR11iSrzBw",
      "atlassian-domain-verification=dXpMb6IBZlmK7X42/O28YWyiXYn0+90NDFEfrPsBAoAoUsAoDiuicnQAmjbUiyVB",
      "mixpanel-domain-verify=b0a9551d-ae06-424e-b251-5e053c1b2197",
      "v=spf1 include:aspmx.sailthru.com include:spf.protection.outlook.com include:_spf.google.com include:_spf.salesforce.com ip4:69.72.40.165 -all",
      "apple-domain-verification=wjlXLroF7LB1M06q",
      "docusign=37466720-ed19-4ae5-aa97-bc2fa5365a70",
      "google-site-verification=kXFB9SEUb6AMT3qjrWDu818ERjxueipwQ-fEtO2QTSo"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:ne5tw8jz@ag.us.dmarcian.com; ruf=mailto:ne5tw8jz@fr.us.dmarcian.com; adkim=s; aspf=s; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.healthline.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Aug 20 00:00:00 2026 GMT",
    "notAfter": "Mar  5 23:59:59 2027 GMT",
    "san": [
      "*.healthline.com",
      "healthline.com"
    ],
    "days_left": 160,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "18.164.174.74",
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
      "origin": "https://sub.healthline.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://healthline.com/"
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
    "count": 39,
    "notable": [
      "shop.healthline.com"
    ],
    "sample": [
      "ally.healthline.com",
      "brand.healthline.com",
      "central-station-staging.healthline.com",
      "central-station.healthline.com",
      "console.healthline.com",
      "corp-cms.healthline.com",
      "corp-stage-cms.healthline.com",
      "dailydose.healthline.com",
      "diabetes.healthline.com",
      "healthline.com",
      "healthywage.healthline.com",
      "idealimage.healthline.com",
      "inline.healthline.com",
      "learn-stage.healthline.com",
      "learn.healthline.com",
      "link.healthline.com",
      "links.dailydose.healthline.com",
      "nutrisystem.healthline.com",
      "post-preprod.healthline.com",
      "post-sandbox.healthline.com"
    ]
  },
  "apex_txt": [
    "facebook-domain-verification=jj8ocu40cbv4gwsxk5zu85eu8is5l2",
    "adobe-idp-site-verification=b6e27597198dfc9921fbe2ad78e9a76012bb17d0ddb65389e600",
    "google-site-verification=10MtyW5tixgJ1zJl41PFoXGHoCT4rEXnxSDi7c9O2xc",
    "google-site-verification=9rByw_q31RzBqs4AA7KUd5DVRtwqu7JaBKtCzREyQ88",
    "_globalsign-domain-verification=gxDZTHFxmg56fm5vMzUelQcu7UZSnIYHxvoZHAUJYR"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/bmajax/",
      "/v2/",
      "/vp/",
      "/corporate/",
      "/health/mirgraine-headaches",
      "/health/wp-*",
      "/nutrition/wp-*",
      "/program/wp-*",
      "/health-news/wp-*",
      "/health/*/wp-*",
      "/nutrition/*/wp-*",
      "/health-news/*/wp-*",
      "/cdn.jwplayer.com/previews/*",
      "/healthy/",
      "/health/sponsored-article-test-do-not-edit-this-ever"
    ]
  },
  "elapsed_s": 20.7,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
