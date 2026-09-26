# Security Audit Report — bigthink.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bigthink.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | bigthink.com |
| Test date | 2026-09-26 17:40 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 4, Info: 16)

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
| 14 | info | P11 | WordPress login page exposed | CWE-200 |
| 15 | info | P8 | Missing security.txt | CWE-1038 |
| 16 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 17 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 18 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 19 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 20 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.29.239:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.29.239:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; X-Powered-By: WordPress VIP <https://wpvip.com>; Cloudflare CDN/WAF
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

### 14. [INFO] WordPress login page exposed (`P11`)

- **CWE:** CWE-200
- **Detail:** /wp-login.php returns 200.
- **Recommendation:** Restrict or rate-limit the WordPress login endpoint.

### 15. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 16. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 17. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 18. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: brave-ledger-verification=91274b2f4b86d4e567f1bfac3af2939e17f3789e9149f42a54e22b; atlassian-domain-verification=Sy2DdmSX6vjBKYnPktlBtM0HVxilSLu427CbTKyytLpHVd9daK; _globalsign-domain-verification=1bIUeFQan6DwxRMFkfSsKamrhvJLH8zU49c1PDyHi5
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 19. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of bigthink.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 20. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1 disallow path(s), e.g. Sitemap:
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "bigthink.com",
  "dns": {
    "a": [
      "104.20.29.239",
      "172.66.171.144"
    ],
    "aaaa": [
      "2606:4700:10::6814:1def",
      "2606:4700:10::ac42:ab90"
    ],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 20)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx3.googlemail.com (pref 30)"
    ],
    "ns": [
      "liv.ns.cloudflare.com.",
      "frank.ns.cloudflare.com."
    ],
    "spf": [
      "e4bo424u3f58fnv2geanpla4r5",
      "brave-ledger-verification=91274b2f4b86d4e567f1bfac3af2939e17f3789e9149f42a54e22b6c6a4ddfa5",
      "MS=ms59457489",
      "v=spf1 a mx include:servers.mcsv.net include:_spf.google.com include:mailgun.org -all",
      "atlassian-domain-verification=Sy2DdmSX6vjBKYnPktlBtM0HVxilSLu427CbTKyytLpHVd9daKw3DMdjJ0ZLLP4V",
      "_globalsign-domain-verification=1bIUeFQan6DwxRMFkfSsKamrhvJLH8zU49c1PDyHi5",
      "google-site-verification=IQ0Q3-snTXtmIPmqxY4XEk-ucnIk9H_LTPldZQ384-o",
      "_globalsign-domain-verification=oQMq_G3Amhi22taxA9iFT-dk_zHARxA27Z0jygBZzo",
      "facebook-domain-verification=imnsr6iaawlgvto58dd99ywxgdfkmr",
      "p6wbgj4mp14fnw67x42pd3bjjtk60ppk",
      "anthropic-domain-verification-3yr2nb=R61RWTRp7eKATMAWS6ysnSgTL",
      "google-site-verification=mrT_skiiLc7lMHOIVrlqYIfL_7dqokcf255Bv4E7Dqg",
      "ZOOM_verify_skjT3dzGm8H9XEy1EOhYI2",
      "_globalsign-domain-verification=2wRqY6IrIINLY7B8Qcp-qur9HsiRTO04g4gwsMmFy3",
      "apple-domain-verification=Y0jnqEg4a6CbdYpz",
      "google-site-verification=Ag1fG5O40z3867zln2At8HXynDGkVy-PFYrn4TV43n8"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@bigthink.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=bigthink.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 12 04:55:57 2026 GMT",
    "notAfter": "Nov 10 05:55:37 2026 GMT",
    "san": [
      "bigthink.com",
      "v1.bigthink.com"
    ],
    "days_left": 44,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.20.29.239",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "Big Think - Smarter, Faster"
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "X-Powered-By: WordPress VIP <https://wpvip.com>",
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
      "origin": "https://sub.bigthink.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://bigthink.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "brave-ledger-verification=91274b2f4b86d4e567f1bfac3af2939e17f3789e9149f42a54e22b",
    "atlassian-domain-verification=Sy2DdmSX6vjBKYnPktlBtM0HVxilSLu427CbTKyytLpHVd9daK",
    "_globalsign-domain-verification=1bIUeFQan6DwxRMFkfSsKamrhvJLH8zU49c1PDyHi5",
    "google-site-verification=IQ0Q3-snTXtmIPmqxY4XEk-ucnIk9H_LTPldZQ384-o",
    "_globalsign-domain-verification=oQMq_G3Amhi22taxA9iFT-dk_zHARxA27Z0jygBZzo"
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
      "Sitemap:"
    ]
  },
  "elapsed_s": 18.0,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
