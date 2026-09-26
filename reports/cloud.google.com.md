# Security Audit Report — cloud.google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cloud.google.com/ |
| Bug bounty program | Google |
| Listed scope domain | cloud.google.com |
| Test date | 2026-09-26 17:41 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 0, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 7 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 8 | info | CK5 | Cookie scoped to parent domain (.google.com) | CWE-200 |
| 9 | info | CT1 | 15 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 6. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=FNbpLNxt8J8XYQAudCNFnig_1bP-LAUSeAePJXlfjzU; linkedin-site-verification=665646e8-9b99-454f-86a2-803db5044863; linkedin-site-verification=d232e0a9-aa43-41a4-8fa4-243021df793a
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 7. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of cloud.google.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 8. [INFO] Cookie scoped to parent domain (.google.com) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host cloud.google.com.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 9. [INFO] 15 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: console.au.cloud.google.com, console.ca.cloud.google.com, console.ch.cloud.google.com, console.eu.cloud.google.com, console.il.cloud.google.com, console.in.cloud.google.com, console.it.cloud.google.com, console.jp.cloud.google.com, console.sa.cloud.google.com, console.uk.cloud.google.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "cloud.google.com",
  "dns": {
    "a": [
      "142.250.198.78"
    ],
    "aaaa": [
      "2404:6800:4012:8::200e"
    ],
    "cname": null,
    "mx": [],
    "ns": [],
    "spf": [
      "google-site-verification=FNbpLNxt8J8XYQAudCNFnig_1bP-LAUSeAePJXlfjzU",
      "linkedin-site-verification=665646e8-9b99-454f-86a2-803db5044863",
      "linkedin-site-verification=d232e0a9-aa43-41a4-8fa4-243021df793a",
      "google-site-verification=jaH5RlwfdutdrKEaZY5nEbcReUEp9rlTOJIuMqh-SV4",
      "facebook-domain-verification=arpzb36y6gfzl22n4jl30bg5fsrgh0",
      "google-site-verification=6nz-JOcA8VP-mmx29RInf7-g6CTloBX9wpmWHlVSMsw"
    ],
    "dmarc": [],
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
    "ip": "142.250.198.78",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "AI and Cloud Computing Services | Google Cloud"
  },
  "mixed_content": [],
  "tech": [
    "Server: ESF"
  ],
  "cookies": [
    {
      "domain": ".google.com",
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
      "origin": "https://sub.cloud.google.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://cloud.google.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 200,
    "/.git/config": 200,
    "/.env": 200,
    "/.htaccess": 200,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 200,
    "/server-status": 200,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 15,
    "notable": [
      "console.au.cloud.google.com",
      "console.ca.cloud.google.com",
      "console.ch.cloud.google.com",
      "console.eu.cloud.google.com",
      "console.il.cloud.google.com",
      "console.in.cloud.google.com",
      "console.it.cloud.google.com",
      "console.jp.cloud.google.com",
      "console.sa.cloud.google.com",
      "console.uk.cloud.google.com",
      "console.us.cloud.google.com",
      "datastudio.eu.cloud.google.com",
      "datastudio.us.cloud.google.com",
      "lookerstudio.eu.cloud.google.com",
      "lookerstudio.us.cloud.google.com"
    ],
    "sample": [
      "console.au.cloud.google.com",
      "console.ca.cloud.google.com",
      "console.ch.cloud.google.com",
      "console.eu.cloud.google.com",
      "console.il.cloud.google.com",
      "console.in.cloud.google.com",
      "console.it.cloud.google.com",
      "console.jp.cloud.google.com",
      "console.sa.cloud.google.com",
      "console.uk.cloud.google.com",
      "console.us.cloud.google.com",
      "datastudio.eu.cloud.google.com",
      "datastudio.us.cloud.google.com",
      "lookerstudio.eu.cloud.google.com",
      "lookerstudio.us.cloud.google.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=FNbpLNxt8J8XYQAudCNFnig_1bP-LAUSeAePJXlfjzU",
    "linkedin-site-verification=665646e8-9b99-454f-86a2-803db5044863",
    "linkedin-site-verification=d232e0a9-aa43-41a4-8fa4-243021df793a",
    "google-site-verification=jaH5RlwfdutdrKEaZY5nEbcReUEp9rlTOJIuMqh-SV4",
    "facebook-domain-verification=arpzb36y6gfzl22n4jl30bg5fsrgh0"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "hsts_preloaded": true
  },
  "elapsed_s": 7.5,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
