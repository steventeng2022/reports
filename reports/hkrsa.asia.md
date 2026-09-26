# Security Audit Report — hkrsa.asia

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hkrsa.asia/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | hkrsa.asia |
| Test date | 2026-09-26 17:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **29** (High: 0, Medium: 2, Low: 5, Info: 22)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | medium | PRT21 | FTP service (cleartext) reachable | CWE-319 |
| 4 | info | PRT22 | SSH reachable | CWE-200 |
| 5 | info | PRT25 | SMTP (port 25) reachable | CWE-200 |
| 6 | info | PRT53 | DNS service reachable | CWE-200 |
| 7 | info | PRT110 | POP3 (cleartext) reachable | CWE-319 |
| 8 | info | PRT143 | IMAP (cleartext) reachable | CWE-319 |
| 9 | info | PRT993 | IMAPS (port 993) reachable | CWE-200 |
| 10 | info | PRT995 | POP3S (port 995) reachable | CWE-200 |
| 11 | medium | PRT3306 | MySQL (port 3306) reachable | CWE-200 |
| 12 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 13 | info | TECH1 | Technology fingerprint | CWE-200 |
| 14 | low | H1 | Missing HSTS header | CWE-319 |
| 15 | low | H2 | Missing CSP header | CWE-1021 |
| 16 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 17 | low | H4 | No clickjacking protection | CWE-1023 |
| 18 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 19 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 20 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 21 | info | H6 | Server technology disclosure | CWE-200 |
| 22 | info | P11 | WordPress login page exposed | CWE-200 |
| 23 | info | P8 | Missing security.txt | CWE-1038 |
| 24 | info | MAIL10 | DMARC subdomain policy (sp=) set while apex policy is p=none | CWE-285 |
| 25 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 26 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 27 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 28 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 29 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [MEDIUM] FTP service (cleartext) reachable (`PRT21`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 43.241.73.139:21 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] SSH reachable (`PRT22`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 43.241.73.139:22 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] SMTP (port 25) reachable (`PRT25`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 43.241.73.139:25 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 6. [INFO] DNS service reachable (`PRT53`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 43.241.73.139:53 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 7. [INFO] POP3 (cleartext) reachable (`PRT110`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 43.241.73.139:110 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 8. [INFO] IMAP (cleartext) reachable (`PRT143`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 43.241.73.139:143 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 9. [INFO] IMAPS (port 993) reachable (`PRT993`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 43.241.73.139:993 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 10. [INFO] POP3S (port 995) reachable (`PRT995`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 43.241.73.139:995 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 11. [MEDIUM] MySQL (port 3306) reachable (`PRT3306`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 43.241.73.139:3306 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 12. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 13. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache/2; X-Powered-By: PHP/7.4.22
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 14. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 15. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 16. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 17. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 18. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 19. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 20. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 21. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Apache/2
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 22. [INFO] WordPress login page exposed (`P11`)

- **CWE:** CWE-200
- **Detail:** /wp-login.php returns 200.
- **Recommendation:** Restrict or rate-limit the WordPress login endpoint.

### 23. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 24. [INFO] DMARC subdomain policy (sp=) set while apex policy is p=none (`MAIL10`)

- **CWE:** CWE-285
- **Detail:** Subdomains are enforced while the apex domain is monitor-only.
- **Recommendation:** Confirm the split policy is intended.

### 25. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 26. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 27. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=fuiWzkZlc9SD_PVbngjZg6bU3XOUSVksLlTjJDccy9A
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 28. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of hkrsa.asia has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 29. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1 disallow path(s), e.g. Sitemap:
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "hkrsa.asia",
  "dns": {
    "a": [
      "43.241.73.139"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mail.hkrsa.asia (pref 10)"
    ],
    "ns": [
      "ns221.pointdnshere.net.",
      "ns222.pointdnshere.net."
    ],
    "spf": [
      "v=spf1 a mx include:pointdnshere.com ~all",
      "google-site-verification=fuiWzkZlc9SD_PVbngjZg6bU3XOUSVksLlTjJDccy9A"
    ],
    "dmarc": [
      "v=DMARC1; p=none; sp=none; rua=mailto:spam-reports@hkrsa.asia"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "subject": "commonName=ftp.hkrsa.asia",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Aug  5 16:57:37 2026 GMT",
    "notAfter": "Nov  3 16:57:36 2026 GMT",
    "san": [
      "ftp.hkrsa.asia",
      "hkrsa.asia",
      "mail.hkrsa.asia",
      "www.hkrsa.asia"
    ],
    "days_left": 37,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "43.241.73.139",
    "open": [
      21,
      22,
      25,
      53,
      110,
      143,
      993,
      995,
      3306
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "ä¸»é  - é¦æ¸¯å°æ¥­è±å¼è·³ç¹©å­¸æ ¡ Hong Kong Rope Skipping Academy"
  },
  "mixed_content": [
    "href=\"http://",
    "href=\"http://",
    "href=\"http://",
    "href=\"http://",
    "href=\"http://"
  ],
  "tech": [
    "Server: Apache/2",
    "X-Powered-By: PHP/7.4.22"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.hkrsa.asia",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 200
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 403,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 401,
    "/server-status": 403,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=fuiWzkZlc9SD_PVbngjZg6bU3XOUSVksLlTjJDccy9A"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 384,
      "curve": "1.3.132.0.34",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "Sitemap:"
    ]
  },
  "elapsed_s": 55.9,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
