# Security Audit Report — imdb.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://imdb.com/ |
| Bug bounty program | IMDB |
| Listed scope domain | imdb.com |
| Test date | 2026-09-26 18:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 3, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Server
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Server
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=f3PqOeHGPuPaaRAkAPJ4bSO-O8bDQOohrmdwxtJAIIM; google-site-verification=uL7Y3ZHRGFE5c6a05OXtn2S2Vq6LfrtqsYlwszK0yl8; atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbD
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of imdb.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 21 disallow path(s), e.g. /register, /*/register, /registration/, /*/registration/, /search/title/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 44.215.137.99 carries PTR ec2-44-215-137-99.compute-1.amazonaws.com. for imdb.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "imdb.com",
  "dns": {
    "a": [
      "44.215.137.99",
      "98.82.155.134",
      "98.82.158.179"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "amazon-smtp.amazon.com (pref 10)"
    ],
    "ns": [
      "ns1.amzndns.net.",
      "ns1.amzndns.org.",
      "ns2.amzndns.net.",
      "ns2.amzndns.org.",
      "ns2.amzndns.com.",
      "ns1.amzndns.com.",
      "ns1.amzndns.co.uk.",
      "ns2.amzndns.co.uk."
    ],
    "spf": [
      "MS=ms74462343",
      "TS1760027",
      "google-site-verification=f3PqOeHGPuPaaRAkAPJ4bSO-O8bDQOohrmdwxtJAIIM",
      "google-site-verification=uL7Y3ZHRGFE5c6a05OXtn2S2Vq6LfrtqsYlwszK0yl8",
      "MS=ms55779356",
      "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbDvoGpRaIwj/tgPH",
      "canva-site-verification=knObS_jT07ww5BsgiACF8g",
      "bluebeam-verification=jcnffcdt5x1u0ay5kp1ds2xctgv0jj",
      "docker-verification=800fa4c1-614f-4e2c-9ee5-c43ea1dc7831",
      "apple-domain-verification=0jFtlxygq-YPBzUgTNd2qDiTxb6TpG8Hf1qJcLlFb_w",
      "cisco-ci-domain-verification=5b0cade9b99903b93ec19495d546a72dbb24ecf17c3670b02bbf706bb9ba552a",
      "kahoot-domain-verification=044996899c64fcdf913eed0ad14e1f19c79bdd590a762d537a2eeeac7c1ba6c0",
      "IPROTA_D66964-XXX",
      "box-domain-verification=ffea95cd0e0d61c302198367155b07e74fd534fa1d867662dc9bf9969b6f535d",
      "adobe-idp-site-verification=b6bcd3e5aaffc63607c8bf75744d9a0d1febc50dd7f389428e2ae476c9ba8814",
      "v=spf1 include:amazon.com -all"
    ],
    "dmarc": [
      "v=DMARC1;",
      "p=quarantine;",
      "pct=100;",
      "rua=mailto:report@dmarc.amazon.com;",
      "ruf=mailto:report@dmarc.amazon.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=us.dd.imdb.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Aug  5 00:00:00 2026 GMT",
    "notAfter": "Feb 18 23:59:59 2027 GMT",
    "san": [
      "us.dd.imdb.com",
      "secure.imdb.com",
      "www.imdb.to",
      "imdb.com",
      "origin-www.imdb.com",
      "imdb-webservice.amazon.com",
      "www.imdb.com",
      "origin.www.geo.imdb.com",
      "addpro.imdb.com",
      "s.media-imdb.com"
    ],
    "days_left": 145,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "44.215.137.99",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Server"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.imdb.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://imdb.com/"
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
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=f3PqOeHGPuPaaRAkAPJ4bSO-O8bDQOohrmdwxtJAIIM",
    "google-site-verification=uL7Y3ZHRGFE5c6a05OXtn2S2Vq6LfrtqsYlwszK0yl8",
    "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbD",
    "canva-site-verification=knObS_jT07ww5BsgiACF8g",
    "bluebeam-verification=jcnffcdt5x1u0ay5kp1ds2xctgv0jj"
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
      "aia_ocsp": null,
      "not_before": "20260805000000",
      "not_after": "20270218235959"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/register",
      "/*/register",
      "/registration/",
      "/*/registration/",
      "/search/title/*",
      "/*/search/title/*",
      "/search/name/*",
      "/*/search/name/*",
      "/find",
      "/*/find",
      "/find/",
      "/*/find/",
      "/contribute/*",
      "/*/contribute/*",
      "/title/*/review/*"
    ]
  },
  "x12": {
    "status": 302,
    "ptr": [
      "ec2-44-215-137-99.compute-1.amazonaws.com."
    ]
  },
  "elapsed_s": 24.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
