# Security Audit Report — infusionsoft.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://infusionsoft.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | infusionsoft.com |
| Test date | 2026-09-26 17:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 5, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 19 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.6.143:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.6.143:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 11. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 15. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 16. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=Zv6aPQO0CFgBxwOk23uUOkmdLjhc9qmcz-UnQcgXkA; google-site-verification=FcoWnWR2MEyLrhy3x0Zkdq_kDaSuLKCkwGYqtOHwOKU; google-site-verification=bEBY3Ylxn8q-_fRzVYwAR9JXNm40sKgOzGs_9TGLzoY
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of infusionsoft.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 19. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 8 disallow path(s), e.g. /resources/thank-you, /resources/thank-you/*, /subscribe/thank-you, /infusionsoft/resources/thank-you, /infusionsoft/resources/thank-you/*
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "infusionsoft.com",
  "dns": {
    "a": [
      "104.18.6.143",
      "104.18.7.143"
    ],
    "aaaa": [
      "2606:4700::6812:68f",
      "2606:4700::6812:78f"
    ],
    "cname": null,
    "mx": [
      "esa1.hc5632-20.iphmx.com (pref 0)",
      "esa2.hc5632-20.iphmx.com (pref 10)"
    ],
    "ns": [
      "alan.ns.cloudflare.com.",
      "dina.ns.cloudflare.com."
    ],
    "spf": [
      "if1d65ukc54m5s6i74bqfe025f",
      "_globalsign-domain-verification=Zv6aPQO0CFgBxwOk23uUOkmdLjhc9qmcz-UnQcgXkA",
      "google-site-verification=FcoWnWR2MEyLrhy3x0Zkdq_kDaSuLKCkwGYqtOHwOKU",
      "google-site-verification=bEBY3Ylxn8q-_fRzVYwAR9JXNm40sKgOzGs_9TGLzoY",
      "google-site-verification=qJt8cbk9zo_KURgheieYf9dmNvIsH4EobNqLCTg6RmQ",
      "google-site-verification=fTsSyDSrHoZk7j9c7SjtCrD9Z1X0E9euuiDd8XomOp4",
      "atlassian-domain-verification=x4AH7fTPG/rMtCvfeaTpcXEW1xxb7P7EU6OgtJogxYDpxaCU8G8y/uTfFrcnND/F",
      "MS=ms82281616",
      "apple-domain-verification=b0zfyw1tbvYfts6I",
      "google-site-verification=8PGA7REJ-oOUYtQ1kt1K-Qb_Zf1y0m2b6LcQgkmENcs",
      "MS=ms27114486",
      "google-site-verification=ecBOxw10e0n8-B8D35IhyVwkRNhRKrx4wSg36211ySw",
      "cisco-ci-domain-verification=75c979906e7b5e9bbf5b674256c43265e545aa031bb6682c75414e290689d078",
      "google-site-verification=aQaRJ7JbSTnc_uFnrueKHNHnkYCYWC4VR5NQmc4nb6o",
      "kiqose9doghqntt26sntbtq0rb",
      "lgu1e2j4g4a4j6lhd9h0g6c07o",
      "google-site-verification=Z8uiYpXNoz6cu19xv6_rJ7GPC0S0ES41FuwA-H4dth4",
      "google-site-verification=f4fZ5SCboZNZoBmJCqcx9r2XLOo3ZGRuS-AhTXsxQdo",
      "v=spf1 ip4:70.166.203.170/31 ip4:70.166.203.172/31 ip4:208.76.24.0/22 ip4:70.166.189.64/29 ip4:167.216.128.0/22 ip4:64.89.44.0/23 ip4:207.211.31.0/25 ip4:208.46.212.0/23 ip4:52.38.191.241",
      " ip4:35.227.130.3 ip4:35.227.130.4/31 include:mktomail.com include:mg-spf.greenhouse.io -all",
      "ajde87b8tq24b4lj2l6q3u6dk4",
      "google-site-verification=nkj81hcbyLz-I-SSFuGa2SjEOK50Ad6OEzr7vIUS0kI",
      "slack-domain-verification=yqhK2KmKgxxjIp4PfZUH1nyIouasR8pVx7w5NIJO",
      "google-site-verification=DertqkC0npNIXrj_ag69XBc2Fu_9_qTB0y0uQp1-D7k",
      "google-site-verification=WftUye_dldiVZJVLg52xTBYm5DxirQYS22c_QTjHxFE",
      "google-site-verification=s-1DswNLnBGEVvlFB5WFaF5MJx0lmUV1C0rK722XUS4",
      "google-site-verification=Y9y0pmN9qgudD_i6qiD7EfKVyHr2M_ID4OZHaeCYI8g",
      "457585744-6110905",
      "google-site-verification=XVUWj8ew581HogPA2mtBUF86np4dAEi5byYIxaG_7iI"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarcreports@infusionsoft.com,mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarcreports-fr@infusionsoft.com,mailto:dmarc_ruf@emaildefense.proofpoint.com; pct=100; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=infusionsoft.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug  7 17:15:10 2026 GMT",
    "notAfter": "Nov  5 18:14:54 2026 GMT",
    "san": [
      "infusionsoft.com",
      "*.infusionsoft.com"
    ],
    "days_left": 40,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.6.143",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
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
      "domain": "infusionsoft.com",
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
      "origin": "https://sub.infusionsoft.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.infusionsoft.com/"
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
    "_globalsign-domain-verification=Zv6aPQO0CFgBxwOk23uUOkmdLjhc9qmcz-UnQcgXkA",
    "google-site-verification=FcoWnWR2MEyLrhy3x0Zkdq_kDaSuLKCkwGYqtOHwOKU",
    "google-site-verification=bEBY3Ylxn8q-_fRzVYwAR9JXNm40sKgOzGs_9TGLzoY",
    "google-site-verification=qJt8cbk9zo_KURgheieYf9dmNvIsH4EobNqLCTg6RmQ",
    "google-site-verification=fTsSyDSrHoZk7j9c7SjtCrD9Z1X0E9euuiDd8XomOp4"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/resources/thank-you",
      "/resources/thank-you/*",
      "/subscribe/thank-you",
      "/infusionsoft/resources/thank-you",
      "/infusionsoft/resources/thank-you/*",
      "/infusionsoft/subscribe/thank-you",
      "/",
      "/"
    ]
  },
  "elapsed_s": 9.3,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
