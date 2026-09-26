# Security Audit Report — myfitnesspal.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://myfitnesspal.com/ |
| Bug bounty program | UNDER ARMOUR |
| Listed scope domain | myfitnesspal.com |
| Test date | 2026-09-25 10:03 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 6, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | low | CORS3 | CORS: external origin accepted with credentials | CWE-942 |
| 15 | low | CORS1 | CORS: subdomain origin origin accepted with credentials | CWE-942 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.153.11:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.153.11:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 12. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [LOW] CORS: external origin accepted with credentials (`CORS3`)

- **CWE:** CWE-942
- **Detail:** Origin https://evil-auditor.example -> Access-Control-Allow-Origin: https://evil-auditor.example, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

### 15. [LOW] CORS: subdomain origin origin accepted with credentials (`CORS1`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.myfitnesspal.com -> Access-Control-Allow-Origin: https://sub.myfitnesspal.com, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

## Evidence (raw response observations)

```json
{
  "domain": "myfitnesspal.com",
  "dns": {
    "a": [
      "172.64.153.11",
      "104.18.34.245"
    ],
    "aaaa": [
      "2a06:98c1:310d::ac40:990b",
      "2606:4700:440a::6812:22f5"
    ],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "elisa.ns.cloudflare.com.",
      "gannon.ns.cloudflare.com."
    ],
    "spf": [
      "loom-site-verification=edd4369291874aacb2b5aae6ea089158",
      "planet-scale-domain-verification-xqrft3=bqeTziO1BFwTrh3fexfLtqTDb",
      "segment-site-verification=xopGmJnxbn2rPzZXsS2fMLslPYUndBeJ",
      "7aff834813804a3ea18721b6bce7740d",
      "stripe-verification=4fa8f2705ed3ca0496b4d680bdec5d74213c22e6c1428282612504c2c55d7558",
      "google-site-verification=gB6gRbVH-PkcwwblYYT_s6peEZ-uOCU4SCN-m6t2-0Q",
      "0r4UVQn/K1PldOhFrE9MoJLiJXfQLSKU+uLPm4Z1uGfGrxtPLbQ+ymZcnBCVIkemqdAFahKrsLodU2cqFkkbtA==",
      "asv=57fab8da76cd7db6399386b2fbb8266e",
      "Pv0TLiWeowXZIsAw68NzAb3SgjY",
      "have-i-been-pwned-verification=37c31c95ebc27a82104fd378e23c6f3e",
      "apple-domain-verification=WCdjJmlbmQSDdvD3",
      "openai-domain-verification=dv-UNBZKzk7GFSRuVEUk4KHWObW",
      "MS=ms95772151",
      "atlassian-domain-verification=vRVlNNYB4Ta6QoLCQtsmdBc6emoab1Jsldy9az8E47tQW4cHajZHsi4rTq4HM0PE",
      "docusign=70668272-5104-4868-af0d-389211541998",
      "GUID=9928b8b1-f83f-4518-bf35-ac7504f9b417",
      "google-site-verification=kHACMEqbYV5qgu3tprf-GnXzWeHvWVHgVncFCiQKlb4",
      "logmein-verification-code=25ce4838-7980-4719-b4c5-e76450a6066f",
      "cursor-domain-verification-f88819=Y8P5LsyqtmltA7MfMr2jwtMiQ",
      "v=spf1 include:mail.zendesk.com include:_spf.google.com include:_spf.qualtrics.com include:sendgrid.net ip4:208.185.229.40/29 -all",
      "status-page-domain-verification=qh3cfw6syrg3",
      "MS=ms15058904",
      "anthropic-domain-verification-1mjwc0=ydAYQut9EZNXEQaKnOtAjzP66",
      "facebook-domain-verification=ckr53ulsmy1vs2dwppppt6xwhtc5fk",
      "asn-verification=113e130f52ef13092231213dbadd8d30f0143c37b2c2744d24b16bfbc770372a",
      "1password-site-verification=VOWKAPWYWZCT5HUOWLC2SAZL5E",
      "ca3-b122d05a919141ba91aba958f04a3a83"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:074cb25249364ef2b4923557da662d24@dmarc-reports.cloudflare.net; ruf=mailto:074cb25249364ef2b4923557da662d24@dmarc-reports.cloudflare.net; ri=3600; sp=reject; pct=100; fo=0:1:d:s;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=myfitnesspal.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 18 20:05:55 2026 GMT",
    "notAfter": "Nov 16 21:05:44 2026 GMT",
    "san": [
      "myfitnesspal.com",
      "*.dev.myfitnesspal.com",
      "*.labs.myfitnesspal.com",
      "*.myfitnesspal.com",
      "dev.myfitnesspal.com"
    ],
    "days_left": 52,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.64.153.11",
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
      "domain": "myfitnesspal.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "https://evil-auditor.example",
      "acac": "true"
    },
    {
      "origin": "https://sub.myfitnesspal.com",
      "acao": "https://sub.myfitnesspal.com",
      "acac": "true"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://myfitnesspal.com/"
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
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 43.3,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
