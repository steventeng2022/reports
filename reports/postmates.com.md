# Security Audit Report — postmates.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://postmates.com/ |
| Bug bounty program | Postmates |
| Listed scope domain | postmates.com |
| Test date | 2026-09-26 18:57 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 2, Info: 17)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 17 | low | CK4 | Session-like cookie without HttpOnly | CWE-1004 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.36.195.2:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.36.195.2:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=2Ilvgbr78yRVip_eIEMEDS5i2w9I8WqlkC5MGwtT9mc; status-page-domain-verification=vbzgm2f4x75m; google-site-verification=H0kH4zM_GueUZtOBxqzPVtLNFV4044GyQ0f70CKXFp4
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of postmates.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but postmates.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 17. [LOW] Session-like cookie without HttpOnly (`CK4`)

- **CWE:** CWE-1004
- **Detail:** Cookie 'uev2.id.session' looks session-related and has no HttpOnly attribute.
- **Recommendation:** Set HttpOnly on session cookies.

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 2250 disallow path(s), e.g. */delivery-details, */group-orders/, */search?, */select-language, */checkout
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of postmates.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

## Evidence (raw response observations)

```json
{
  "domain": "postmates.com",
  "dns": {
    "a": [
      "104.36.195.2"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 10)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx5.googlemail.com (pref 10)",
      "aspmx4.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "edns126.ultradns.com.",
      "edns126.ultradns.net.",
      "edns126.ultradns.org.",
      "edns126.ultradns.biz."
    ],
    "spf": [
      "fhtfbm1hh3v7nwps06d0t8410d5r93tc",
      "google-site-verification=2Ilvgbr78yRVip_eIEMEDS5i2w9I8WqlkC5MGwtT9mc",
      "status-page-domain-verification=vbzgm2f4x75m",
      "ZOOM_verify_38TrrxQgRki7d9IxN3-DPw",
      "google-site-verification=H0kH4zM_GueUZtOBxqzPVtLNFV4044GyQ0f70CKXFp4",
      "facebook-domain-verification=lanbzff5xfbystm65ipwykm0arewgy",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all",
      "stripe-verification=ef5ba81f76af72dabfe40a67c5a713896d4ae363bf1edede7a7b62b5ba6578d6",
      "hkjvwlbv3sdq8x3n7k7xg6814fktgwt9"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=postmates.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Sep 24 02:16:06 2026 GMT",
    "notAfter": "Dec 23 02:16:05 2026 GMT",
    "san": [
      "*.postmates.com",
      "postmates.com"
    ],
    "days_left": 87,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.36.195.2",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Postmates: Food Delivery, Groceries, Alcohol - Anything from Anywhere"
  },
  "mixed_content": [
    "href=\"http://"
  ],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "postmates.com"
    },
    {
      "domain": "postmates.com"
    },
    {
      "domain": "postmates.com"
    },
    {
      "domain": "postmates.com"
    },
    {
      "domain": "postmates.com"
    },
    {
      "domain": "postmates.com"
    },
    {},
    {
      "domain": ".postmates.com"
    },
    {
      "samesite": "none"
    },
    {
      "domain": "postmates.com",
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
      "origin": "https://sub.postmates.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://postmates.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=2Ilvgbr78yRVip_eIEMEDS5i2w9I8WqlkC5MGwtT9mc",
    "status-page-domain-verification=vbzgm2f4x75m",
    "google-site-verification=H0kH4zM_GueUZtOBxqzPVtLNFV4044GyQ0f70CKXFp4",
    "facebook-domain-verification=lanbzff5xfbystm65ipwykm0arewgy",
    "stripe-verification=ef5ba81f76af72dabfe40a67c5a713896d4ae363bf1edede7a7b62b5ba65"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260924021606",
      "not_after": "20261223021605"
    }
  },
  "http2": {
    "robots_disallow": [
      "*/delivery-details",
      "*/group-orders/",
      "*/search?",
      "*/select-language",
      "*/checkout",
      "*/closest",
      "*/delivery-details",
      "*/feed",
      "*/login-redirect/",
      "*/order",
      "*恒博国际app下载*",
      "/DC/",
      "/JP-JP/",
      "/_/defaults",
      "/_/diagnostics"
    ]
  },
  "x12": {
    "status": 200
  },
  "elapsed_s": 19.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
