# Security Audit Report — youtube.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://youtube.com/ |
| Bug bounty program | Google |
| Listed scope domain | youtube.com |
| Test date | 2026-09-26 19:02 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 1, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 8 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 9 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 12 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 13 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 14 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ESF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ESF
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 7. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 8. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 9. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=QtQWEwHWM8tHiJ4s-jJWzEQrD_fF3luPnpzNDH-Nw-w; facebook-domain-verification=64jdes7le4h7e7lfpi22rijygx58j1
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of youtube.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 22 disallow path(s), e.g. User-agent:, /api/, /channel_picker, /comment, /feeds/videos.xml
- **Recommendation:** Review disallowed paths; robots is not access control.

### 12. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of youtube.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 13. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of youtube.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 14. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://youtube.com/ carries Cache-Control: private, max-age=31536000; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 142.250.196.206 carries PTR nctsaa-ac-in-f14.1e100.net. for youtube.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "youtube.com",
  "dns": {
    "a": [
      "142.250.196.206"
    ],
    "aaaa": [
      "2404:6800:4012:6::200e"
    ],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 0)"
    ],
    "ns": [
      "ns2.google.com.",
      "ns4.google.com.",
      "ns3.google.com.",
      "ns1.google.com."
    ],
    "spf": [
      "google-site-verification=QtQWEwHWM8tHiJ4s-jJWzEQrD_fF3luPnpzNDH-Nw-w",
      "v=spf1 include:google.com mx -all",
      "facebook-domain-verification=64jdes7le4h7e7lfpi22rijygx58j1"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.google.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR2",
    "notBefore": "Sep 10 19:21:53 2026 GMT",
    "notAfter": "Dec  3 19:21:52 2026 GMT",
    "san": [
      "*.google.com",
      "*.appengine.google.com",
      "*.bdn.dev",
      "*.origin-test.bdn.dev",
      "*.cloud.google.com",
      "*.crowdsource.google.com",
      "*.datacompute.google.com",
      "*.google.ca",
      "*.google.cl",
      "*.google.co.in",
      "*.google.co.jp",
      "*.google.co.uk",
      "*.google.com.ar",
      "*.google.com.au",
      "*.google.com.br",
      "*.google.com.co",
      "*.google.com.mx",
      "*.google.com.tr",
      "*.google.com.vn",
      "*.google.de",
      "*.google.es",
      "*.google.fr",
      "*.google.hu",
      "*.google.it",
      "*.google.nl",
      "*.google.pl",
      "*.google.pt",
      "*.gemini.cloud.google.com",
      "*.gstatic.com",
      "*.metric.gstatic.com",
      "*.gvt1.com",
      "*.gcpcdn.gvt1.com",
      "*.gvt2.com",
      "*.gcp.gvt2.com",
      "*.url.google.com",
      "*.youtube-nocookie.com",
      "*.ytimg.com",
      "ai.android",
      "android.com",
      "*.android.com",
      "*.flash.android.com",
      "g.co",
      "*.g.co",
      "goo.gl",
      "www.goo.gl",
      "google-analytics.com",
      "*.google-analytics.com",
      "google.com",
      "googlecommerce.com",
      "*.googlecommerce.com",
      "urchin.com",
      "*.urchin.com",
      "youtu.be",
      "youtube.com",
      "*.youtube.com",
      "music.youtube.com",
      "*.music.youtube.com",
      "youtubeeducation.com",
      "*.youtubeeducation.com",
      "youtubekids.com",
      "*.youtubekids.com",
      "yt.be",
      "*.yt.be",
      "android.clients.google.com",
      "*.aistudio.google.com"
    ],
    "days_left": 68,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "142.250.196.206",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: ESF"
  ],
  "cookies": [
    {
      "domain": ".youtube.com",
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
      "origin": "https://sub.youtube.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://youtube.com/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=QtQWEwHWM8tHiJ4s-jJWzEQrD_fF3luPnpzNDH-Nw-w",
    "facebook-domain-verification=64jdes7le4h7e7lfpi22rijygx58j1"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260910192153",
      "not_after": "20261203192152"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "User-agent:",
      "/api/",
      "/channel_picker",
      "/comment",
      "/feeds/videos.xml",
      "/file_download",
      "/get_video",
      "/get_video_info",
      "/get_midroll_info",
      "/live_chat",
      "/login",
      "/qr",
      "/results",
      "/signup",
      "/t/terms"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "nctsaa-ac-in-f14.1e100.net."
    ]
  },
  "elapsed_s": 3.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
