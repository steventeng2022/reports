# Security Audit Report — notion.so

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://notion.so/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | notion.so |
| Test date | 2026-09-26 17:50 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **35** (High: 0, Medium: 9, Low: 2, Info: 24)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | PRT21 | FTP service (cleartext) reachable | CWE-319 |
| 3 | info | PRT22 | SSH reachable | CWE-200 |
| 4 | medium | PRT23 | Telnet service (cleartext) reachable | CWE-319 |
| 5 | info | PRT25 | SMTP (port 25) reachable | CWE-200 |
| 6 | info | PRT53 | DNS service reachable | CWE-200 |
| 7 | info | PRT110 | POP3 (cleartext) reachable | CWE-319 |
| 8 | info | PRT143 | IMAP (cleartext) reachable | CWE-319 |
| 9 | info | PRT993 | IMAPS (port 993) reachable | CWE-200 |
| 10 | info | PRT995 | POP3S (port 995) reachable | CWE-200 |
| 11 | medium | PRT1433 | MSSQL (port 1433) reachable | CWE-200 |
| 12 | medium | PRT3306 | MySQL (port 3306) reachable | CWE-200 |
| 13 | info | PRT3389 | RDP (port 3389) reachable | CWE-200 |
| 14 | medium | PRT5432 | PostgreSQL (port 5432) reachable | CWE-200 |
| 15 | medium | PRT5900 | VNC (port 5900) reachable | CWE-200 |
| 16 | medium | PRT6379 | Redis (port 6379) reachable | CWE-200 |
| 17 | info | PRT8000 | Alternate web service (port 8000) reachable | CWE-200 |
| 18 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 19 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 20 | info | PRT8888 | Alternate web service (port 8888) reachable | CWE-200 |
| 21 | info | PRT9090 | Service (port 9090, e.g. Elasticsearch/debug) reachable | CWE-200 |
| 22 | medium | PRT9200 | Elasticsearch (port 9200) reachable | CWE-200 |
| 23 | medium | PRT27017 | MongoDB (port 27017) reachable | CWE-200 |
| 24 | info | TECH1 | Technology fingerprint | CWE-200 |
| 25 | low | H2 | Missing CSP header | CWE-1021 |
| 26 | low | H4 | No clickjacking protection | CWE-1023 |
| 27 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 28 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 29 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 30 | info | H6 | Server technology disclosure | CWE-200 |
| 31 | info | P8 | Missing security.txt | CWE-1038 |
| 32 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 33 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 34 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 35 | info | CT1 | 70 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [MEDIUM] FTP service (cleartext) reachable (`PRT21`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 208.103.161.17:21 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] SSH reachable (`PRT22`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:22 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [MEDIUM] Telnet service (cleartext) reachable (`PRT23`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 208.103.161.17:23 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] SMTP (port 25) reachable (`PRT25`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:25 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 6. [INFO] DNS service reachable (`PRT53`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:53 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 7. [INFO] POP3 (cleartext) reachable (`PRT110`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 208.103.161.17:110 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 8. [INFO] IMAP (cleartext) reachable (`PRT143`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 208.103.161.17:143 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 9. [INFO] IMAPS (port 993) reachable (`PRT993`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:993 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 10. [INFO] POP3S (port 995) reachable (`PRT995`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:995 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 11. [MEDIUM] MSSQL (port 1433) reachable (`PRT1433`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:1433 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 12. [MEDIUM] MySQL (port 3306) reachable (`PRT3306`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:3306 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 13. [INFO] RDP (port 3389) reachable (`PRT3389`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:3389 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 14. [MEDIUM] PostgreSQL (port 5432) reachable (`PRT5432`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:5432 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 15. [MEDIUM] VNC (port 5900) reachable (`PRT5900`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:5900 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 16. [MEDIUM] Redis (port 6379) reachable (`PRT6379`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:6379 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 17. [INFO] Alternate web service (port 8000) reachable (`PRT8000`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:8000 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 18. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 19. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 20. [INFO] Alternate web service (port 8888) reachable (`PRT8888`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:8888 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 21. [INFO] Service (port 9090, e.g. Elasticsearch/debug) reachable (`PRT9090`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:9090 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 22. [MEDIUM] Elasticsearch (port 9200) reachable (`PRT9200`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:9200 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 23. [MEDIUM] MongoDB (port 27017) reachable (`PRT27017`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 208.103.161.17:27017 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 24. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 25. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 26. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 27. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 28. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 29. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 30. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 31. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 32. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: facebook-domain-verification=2agf76ffad9vxlxya597jrzil7xoxf; google-site-verification=01Xid8U6cE4LuiG2OeRTL-hnDC9MxKvVD6mAgAS51Oo; google-site-verification=_aahlmtDiPlbg224pU3M_8w9Ka-3tcGUmBd6ZW052AU
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 33. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of notion.so has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 34. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 16 disallow path(s), e.g. /invite/, /*/invite/, /templates/search?query=*, /*/templates/search?query=*, /experiment/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 35. [INFO] 70 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.notion.so, api.mail.dev.notion.so, api.mail.notion.so, api.pgncs.notion.so, app.mail.dev.notion.so, app.mail.notion.so, cspreports.mail.dev.notion.so, cspreports.mail.notion.so, dev.notion.so, development.notion.so
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "notion.so",
  "dns": {
    "a": [
      "208.103.161.17",
      "208.103.161.16",
      "208.103.161.1",
      "208.103.161.2"
    ],
    "aaaa": [
      "2602:f79a::2",
      "2602:f79a::1",
      "2602:f79a:0:1::1",
      "2602:f79a:0:1::2"
    ],
    "cname": null,
    "mx": [],
    "ns": [
      "dana.ns.cloudflare.com.",
      "woz.ns.cloudflare.com."
    ],
    "spf": [
      "facebook-domain-verification=2agf76ffad9vxlxya597jrzil7xoxf",
      "proxy-ssl.webflow.com",
      "_eohaffzltripfzavo0ehlmi84k0tkxw",
      "v=spf1 ~all",
      "google-site-verification=01Xid8U6cE4LuiG2OeRTL-hnDC9MxKvVD6mAgAS51Oo",
      "google-site-verification=_aahlmtDiPlbg224pU3M_8w9Ka-3tcGUmBd6ZW052AU",
      "google-site-verification=U2r6h9FWkKMadZDxW94daNJ1YUGXP-9_tJ7PUYfYz4c",
      "google-site-verification=LBOGI6TChsA_9vwaJYLU7RXgunDGAWKG0fcHxiU2-o4"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=100; rua=mailto:re+1b3a27dd30bc@inbound.dmarcdigests.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=notion.so",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 13 22:59:48 2026 GMT",
    "notAfter": "Nov 11 23:59:35 2026 GMT",
    "san": [
      "notion.so",
      "*.notion.so",
      "*.dev.notion.so",
      "*.stg.notion.so",
      "*.www.notion.so"
    ],
    "days_left": 46,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "208.103.161.17",
    "open": [
      21,
      22,
      23,
      25,
      53,
      110,
      143,
      993,
      995,
      1433,
      3306,
      3389,
      5432,
      5900,
      6379,
      8000,
      8080,
      8443,
      8888,
      9090,
      9200,
      27017
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
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.notion.so",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://notion.so/"
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
    "source": "crt.sh",
    "count": 70,
    "notable": [
      "admin.notion.so",
      "api.mail.dev.notion.so",
      "api.mail.notion.so",
      "api.pgncs.notion.so",
      "app.mail.dev.notion.so",
      "app.mail.notion.so",
      "cspreports.mail.dev.notion.so",
      "cspreports.mail.notion.so",
      "dev.notion.so",
      "development.notion.so",
      "identity.dev.notion.so",
      "mail-resource-proxy.mail.dev.notion.so",
      "mail-resource-proxy.mail.notion.so",
      "mail.dev.notion.so",
      "mail.notion.so"
    ],
    "sample": [
      "admin-dev.notion.so",
      "admin-prod.notion.so",
      "admin-stg.notion.so",
      "admin.notion.so",
      "affiliate.notion.so",
      "aif.notion.so",
      "analytics-iframe.notion.so",
      "analytics.pgncs.notion.so",
      "api.mail.dev.notion.so",
      "api.mail.notion.so",
      "api.pgncs.notion.so",
      "app.mail.dev.notion.so",
      "app.mail.notion.so",
      "calendar-api-dev.notion.so",
      "calendar-api-stg.notion.so",
      "calendar-api.notion.so",
      "calendar-dev.notion.so",
      "calendar-stg.notion.so",
      "calendar-test.notion.so",
      "calendar.notion.so"
    ]
  },
  "apex_txt": [
    "facebook-domain-verification=2agf76ffad9vxlxya597jrzil7xoxf",
    "google-site-verification=01Xid8U6cE4LuiG2OeRTL-hnDC9MxKvVD6mAgAS51Oo",
    "google-site-verification=_aahlmtDiPlbg224pU3M_8w9Ka-3tcGUmBd6ZW052AU",
    "google-site-verification=U2r6h9FWkKMadZDxW94daNJ1YUGXP-9_tJ7PUYfYz4c",
    "google-site-verification=LBOGI6TChsA_9vwaJYLU7RXgunDGAWKG0fcHxiU2-o4"
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
    "hsts_preloaded": true,
    "robots_disallow": [
      "/invite/",
      "/*/invite/",
      "/templates/search?query=*",
      "/*/templates/search?query=*",
      "/experiment/*",
      "/*/experiment/*",
      "/lp/webinars/",
      "/lp/webinars/*",
      "/_vercel/insights/view",
      "/embed/*",
      "/*/embed/*",
      "/",
      "/",
      "/",
      "/"
    ]
  },
  "elapsed_s": 4.9,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
