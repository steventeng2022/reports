# Security Audit Report — foxnews.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://foxnews.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | foxnews.com |
| Test date | 2026-09-25 09:46 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
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
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=86400 (< 31536000).
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
- **Detail:** Header reveals: AkamaiGHost
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
  "domain": "foxnews.com",
  "dns": {
    "a": [
      "23.41.37.149"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-00195501.gslb.pphosted.com (pref 10)",
      "mxa-00195501.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns03.foxdoua.com.",
      "ns04.foxdoua.com.",
      "ns04.dns.fox.",
      "ns01.dns.fox.",
      "ns02.foxdoua.com.",
      "ns02.dns.fox.",
      "ns01.foxdoua.com.",
      "ns03.dns.fox."
    ],
    "spf": [
      "tiktok-developers-site-verification=lSBeuScXrGuauVFWLkvyQxleQhAO10IK",
      "MS=ms40284671",
      "v=spf1 ip4:208.84.65.98 ip4:208.86.201.96 include:spf-00195501.pphosted.com include:spf.protection.outlook.com include:amazonses.com include:mail.zendesk.com include:_spf.google.com -all",
      "bppko2051pbcn9bvdualgach7h",
      "postman-domain-verification=da8272c2c9fcb2ddec634c78ae9e618519672e19811f32cef729d317fa89e261",
      "google-site-verification=3LvSKyvB7eXlZQtS_7fwgd0cMKh6zBBzo-g9hhEVu7k",
      "265947818-2009536",
      "MS=ms71309079",
      "qRWnq9UOByGW6DnvW8qZ4scp8GbkRYG4bsmSOyP+dzlIB+XXQtkNbpBK3qVrJ8E7YT83Bk33z5CPO1L2KlH/mA==",
      "_globalsign-domain-verification=BahbT-Pu-HaLP9bBimZ0MGe-4CPc4Z_MXqKNUajBmF",
      "_4ywk6miyhayot1r60tb3ubei8wl9mvi",
      "adobe-idp-site-verification=10f6011913207e944a026129f59881b0cb1078801a8c11229c6e95615eb28070"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=Fox News Network, LLC, commonName=wildcard.foxnews.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Feb 24 00:00:00 2026 GMT",
    "notAfter": "Feb 24 23:59:59 2027 GMT",
    "san": [
      "wildcard.foxnews.com",
      "dev-try.nation.foxnews.com",
      "dev-video.foxbusiness.com",
      "dev-video.foxnews.com",
      "events.foxnews.com",
      "feeds.foxbusiness.com",
      "feeds.foxnews.com",
      "foxbusiness.com",
      "foxnews.com",
      "foxnewsinsider.com",
      "foxnewsinternational.com",
      "hp-cms.foxbusiness.com",
      "hp-cms.foxnews.com",
      "hp.cms.foxnews.com",
      "hp.dev-cms.foxnews.com",
      "hp.staging-cms.foxnews.com",
      "liveblog-cms.foxbusiness.com",
      "liveblog-cms.foxnews.com",
      "pre-try.nation.foxnews.com",
      "public.media.foxnews.com",
      "qa.global.fncstatic.com",
      "secure.media.foxnews.com",
      "stage-pre-try.nation.foxnews.com",
      "stage-try.nation.foxnews.com",
      "stage-video.foxbusiness.com",
      "stage-video.foxnews.com",
      "try.nation.foxnews.com",
      "ak.podcast-testing.foxnewsradio.com",
      "ak.cuts.foxnewsradio.com",
      "affiliates.radio.foxnews.com",
      "*.foxnewsradio.com",
      "*.foxnewsinternational.com",
      "*.foxnews.com",
      "*.foxbusiness.com",
      "*.fncstatic.com",
      "*.fbnstatic.com",
      "beta.video.magazine.foxnews.com",
      "beta.video.latino.foxnews.com",
      "beta.video.insider.foxnews.com",
      "beta.video.foxbusiness.com",
      "ak.premium.foxnewsradio.com",
      "beta.video.foxnews.com",
      "ak.podcast.foxnewsradio.com"
    ],
    "days_left": 152,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.41.37.149",
    "open": []
  },
  "https": {
    "status": 301,
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
      "origin": "https://sub.foxnews.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://foxnews.com/"
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
  "elapsed_s": 44.8,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
