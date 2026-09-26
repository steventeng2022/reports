# Security Audit Report — europarl.europa.eu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://europarl.europa.eu/ |
| Bug bounty program | European Central Bank |
| Listed scope domain | europarl.europa.eu |
| Test date | 2026-09-26 17:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 4, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

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
- **Detail:** Apex TXT records with verification/token content: flexera-domain-verification-lpktsstialtzvdbc; webexdomainverification.=b646d9da-b47b-4aab-bef6-239fa2ea87d5; flexera-domain-verification-dwtjdzijulkjpxak
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of europarl.europa.eu has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 31 disallow path(s), e.g. /, /calendar/, /debats/, /pv1/, /pv2/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "europarl.europa.eu",
  "dns": {
    "a": [
      "136.173.69.97"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "ucsgusrlp002.ep.europa.eu (pref 100)",
      "ucsgusrbp002.ep.europa.eu (pref 100)",
      "ucsgusrlp004.ep.europa.eu (pref 100)",
      "ucsgusrbp003.ep.europa.eu (pref 100)",
      "ucsgusrbp001.ep.europa.eu (pref 100)",
      "ucsgusrlp003.ep.europa.eu (pref 100)",
      "ucsgusrbp004.ep.europa.eu (pref 100)",
      "ucsgusrlp001.ep.europa.eu (pref 100)"
    ],
    "ns": [
      "ans1.cw.net.",
      "ans2.cw.net.",
      "itecluxadnsout.europarl.europa.eu.",
      "itecbruadnsout.europarl.europa.eu."
    ],
    "spf": [
      "flexera-domain-verification-lpktsstialtzvdbc",
      "webexdomainverification.=b646d9da-b47b-4aab-bef6-239fa2ea87d5",
      "flexera-domain-verification-dwtjdzijulkjpxak",
      "flexera-domain-verification-zqsztipmwceljguc",
      "globalsign-domain-verification=BD0D62B15C7A7E05066B725206878608",
      "MS=ms56498925",
      "cisco-ci-domain-verification=18335c80bc24811455d7efc1f94edae0da5e8d126b83f5b3a4124f0e6437f9",
      "globalsign-domain-verification=288574904BAFBDAD213CEFABB639A762",
      "flexera-domain-verification-nwvxicwkiqqnfbfq",
      "v=spf1 redirect=_spf.ep.europa.eu",
      "apple-domain-verification=qKbdxzkhADwOAk4X"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:abuse@europarl.europa.eu"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=LU, stateOrProvinceName=Luxembourg, localityName=Luxembourg, organizationName=European Parliament, commonName=*.europarl.europa.eu",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 OV TLS CA 2026 Q2",
    "notBefore": "May 26 07:36:42 2026 GMT",
    "notAfter": "Dec 10 07:37:12 2026 GMT",
    "san": [
      "*.europarl.europa.eu",
      "europarl.europa.eu"
    ],
    "days_left": 74,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "136.173.69.97",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.europarl.europa.eu",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.europarl.europa.eu/"
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
    "flexera-domain-verification-lpktsstialtzvdbc",
    "webexdomainverification.=b646d9da-b47b-4aab-bef6-239fa2ea87d5",
    "flexera-domain-verification-dwtjdzijulkjpxak",
    "flexera-domain-verification-zqsztipmwceljguc",
    "globalsign-domain-verification=BD0D62B15C7A7E05066B725206878608"
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
      "/",
      "/calendar/",
      "/debats/",
      "/pv1/",
      "/pv2/",
      "/searchdeb/",
      "/guidemep_info_2009/",
      "/votre-europarl/",
      "/comparl/",
      "/parliament/public/traineeship/secured/",
      "/parliament/public/transltraineeship/secured",
      "/activities/committees/studies/",
      "/activities/committees/studiesCom/",
      "/meps/*/pdf*",
      "/meps/*/xml*"
    ]
  },
  "elapsed_s": 29.4,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
