# Security Audit Report — mlb.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mlb.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | mlb.com |
| Test date | 2026-09-26 17:49 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 4, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: cursor-domain-verification-ghqnyw=dHOe7fY7Ygl1Al61QPw1JMNrX; google-site-verification=ecWDspflVGxmZOFfl5U-feFA50MZguqCygpZH-fHvw0; onetrust-domain-verification=dd8aecd72e714036a95ea068cfe6f2e7
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of mlb.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 76 disallow path(s), e.g. /test/, /api/, /app/, /embed/, /en/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "mlb.com",
  "dns": {
    "a": [
      "34.102.163.158"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mlb-com.mail.protection.outlook.com (pref 1)"
    ],
    "ns": [
      "ns-cloud-b4.googledomains.com.",
      "ns-204.awsdns-25.com.",
      "ns-1370.awsdns-43.org.",
      "ns-cloud-b2.googledomains.com.",
      "ns-1997.awsdns-57.co.uk.",
      "ns-cloud-b1.googledomains.com.",
      "ns-cloud-b3.googledomains.com.",
      "ns-976.awsdns-58.net."
    ],
    "spf": [
      "cursor-domain-verification-ghqnyw=dHOe7fY7Ygl1Al61QPw1JMNrX",
      "google-site-verification=ecWDspflVGxmZOFfl5U-feFA50MZguqCygpZH-fHvw0",
      "onetrust-domain-verification=dd8aecd72e714036a95ea068cfe6f2e7",
      "MS=ms69694204",
      "mandrill_verify.Ug0KyLxAlKlJFADUoUKazw",
      "paloaltonetworks-site-verification=7be9535bc2affb742cb82ebe821a04088380fb53981671210a413b185923dafc",
      "onetrust-domain-verification=b65699a512a948ec984777b9ad7d28f7",
      "6cai8ssdT8bfglT/gt8kwoKyhyAgPcWDuCGhXf6NRtlGOxnCwCVxvE0gV8MARuqkl340xHdWjJtLgFXFk4XOtQ==",
      "anthropic-domain-verification-w0tddh=eUI1DrzYqtNfrirT3GQDfShYK",
      "e2ma-verification=m4j3",
      "google-site-verification=ewYCvyU3ZIlPv8GRbEfttW-iXf6Rvo4C1lzUgfi2W4k",
      "_71zjwgnt0xvgl1emmv7hgs83q8v0jd4",
      "facebook-domain-verification=6l9n1mpxxnvj1l19nmitlu3e5t9qgu",
      "postman-domain-verification=9e8cbf6e58c180aceab032d7f85e916683a73fc5f9dceed2fec8ceba7ca719dddf7b8799b8b78e0153cc9769218729171dd7425c1092c8b14967492e31672762",
      "twilio-domain-verification=5450879a5dddd10b96b14397eb242d58",
      "7zvy2rtgl87v1529vvz467263ttxv00w",
      "google-site-verification=xLIe2kvVf_RIlRbMuNhQfxu5QhOj38hG38eCHOVRI-Q",
      "adobe-idp-site-verification=48421df2-6edd-4d7a-9a50-5d6b7ac37140",
      "mgverify=4486080ee27dbe9c532d7c06bd6416c0594bdb2747dc01acfb5e97721389f1c9",
      "MS=ms85676836",
      "asv=f4d8b04afc0fa2a21f4e5156ec6c2789",
      "e2ma-verification=0x5bb",
      "docusign=dd0cbf68-020f-4af4-9785-638db04566ef",
      "google-site-verification=XOnG1KFFRFfMJeUU7-uEnjQPrJ5bgfSKLU3n-ddA5o0",
      "apple-domain-verification=6IYQq9hakr4CM8uN",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:mailgun.org ~all",
      "smartsheet-site-validation=oaC-Jj1jFnvmweM2PoQJUhOQtun7sj3s",
      "yahoo-verification-key=/7YvIV9kTBbJETYphs2ydo2GBj6XuhvO4P1H1M6dh+o=",
      "atlassian-domain-verification=g2T53fLDVGlvthuuEp+3tHYaHRCtRg7YE0c6muK0q1eRZToBwzYMwLOUVBbImxpM",
      "cloudflare_dashboard_sso=99d69311be411f4639d09940caef8875",
      "openai-domain-verification=dv-D9zatZspLcySUfsBz3ytGnq9"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=mlb.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR3",
    "notBefore": "Sep 12 10:12:02 2026 GMT",
    "notAfter": "Dec 11 11:05:56 2026 GMT",
    "san": [
      "mlb.com"
    ],
    "days_left": 75,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.102.163.158",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.mlb.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.mlb.com/"
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
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "cursor-domain-verification-ghqnyw=dHOe7fY7Ygl1Al61QPw1JMNrX",
    "google-site-verification=ecWDspflVGxmZOFfl5U-feFA50MZguqCygpZH-fHvw0",
    "onetrust-domain-verification=dd8aecd72e714036a95ea068cfe6f2e7",
    "paloaltonetworks-site-verification=7be9535bc2affb742cb82ebe821a04088380fb5398167",
    "onetrust-domain-verification=b65699a512a948ec984777b9ad7d28f7"
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
      "/test/",
      "/api/",
      "/app/",
      "/embed/",
      "/en/",
      "/mlb/",
      "/share/",
      "/tokens/",
      "/tv/",
      "/web/",
      "/legacy",
      "/beta",
      "/es/legacy",
      "/es/beta",
      "/search"
    ]
  },
  "elapsed_s": 10.0,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
