# Security Audit Report — lmgtfy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://lmgtfy.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | lmgtfy.com |
| Test date | 2026-09-26 17:48 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 5, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 12 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 15 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 16 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 19 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 20 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 21 | info | CT1 | 6 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

### 3. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Heroku
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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
- **Detail:** Header reveals: Heroku
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 12. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.lmgtfy.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 15. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 16. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (sj5l9qg12ck2f3.lmgtfy.com and 4y3anla7oaf6pj.lmgtfy.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=exfIwqRniT2rsPd2sDsMz5T19r0dqL7isibd--oVZLM; google-site-verification=9hYmfh01IK_jYdX0bmBW8neNpJaBHFwlyeWgTC6jenU; google-site-verification=k61zckJgSciuGexCcNESZhBUNhs_72dxkZJRB9Yd1Oc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of lmgtfy.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 19. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but lmgtfy.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 20. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 2 disallow path(s), e.g. #, /*qtype=search
- **Recommendation:** Review disallowed paths; robots is not access control.

### 21. [INFO] 6 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.lmgtfy.com, blog.lmgtfy.com, shop.lmgtfy.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "lmgtfy.com",
  "dns": {
    "a": [
      "99.83.220.108",
      "35.71.179.82",
      "13.248.244.96",
      "75.2.60.68"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 30)",
      "aspmx4.googlemail.com (pref 30)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx5.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "ns3.dnsimple.com.",
      "ns1.dnsimple.com.",
      "ns4.dnsimple.com.",
      "ns2.dnsimple.com."
    ],
    "spf": [
      "SEARCH_SAFER_INC_OWNS_LMGTFY_COM",
      "google-site-verification=exfIwqRniT2rsPd2sDsMz5T19r0dqL7isibd--oVZLM",
      "google-site-verification=9hYmfh01IK_jYdX0bmBW8neNpJaBHFwlyeWgTC6jenU",
      "google-site-verification=k61zckJgSciuGexCcNESZhBUNhs_72dxkZJRB9Yd1Oc",
      "google-site-verification=3XLdZhUjpU6Y-BX4FPOeXDUP7W3WnpqtzWEJy2Yx5yE",
      "facebook-domain-verification=zcrcalu1jcrr2kzzo618qpli028r9l",
      "v=spf1 a mx include:_spf.google.com include:cmail1.com include:spf.mtasv.net ~all"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.lmgtfy.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Aug  4 07:07:08 2026 GMT",
    "notAfter": "Nov  2 07:07:07 2026 GMT",
    "san": [
      "*.lmgtfy.com",
      "lmgtfy.com"
    ],
    "days_left": 36,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "99.83.220.108",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "LMGTFY - Let Me Google That For You"
  },
  "mixed_content": [
    "href=\"http://"
  ],
  "tech": [
    "Server: Heroku"
  ],
  "cookies": [
    {
      "samesite": "lax"
    },
    {
      "samesite": "lax"
    },
    {
      "domain": "lmgtfy.com",
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.lmgtfy.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://lmgtfy.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
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
    "source": "certspotter",
    "count": 6,
    "notable": [
      "api.lmgtfy.com",
      "blog.lmgtfy.com",
      "shop.lmgtfy.com"
    ],
    "sample": [
      "api.lmgtfy.com",
      "blog.lmgtfy.com",
      "lmgtfy.com",
      "report.lmgtfy.com",
      "shop.lmgtfy.com",
      "www.lmgtfy.com"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=exfIwqRniT2rsPd2sDsMz5T19r0dqL7isibd--oVZLM",
    "google-site-verification=9hYmfh01IK_jYdX0bmBW8neNpJaBHFwlyeWgTC6jenU",
    "google-site-verification=k61zckJgSciuGexCcNESZhBUNhs_72dxkZJRB9Yd1Oc",
    "google-site-verification=3XLdZhUjpU6Y-BX4FPOeXDUP7W3WnpqtzWEJy2Yx5yE",
    "facebook-domain-verification=zcrcalu1jcrr2kzzo618qpli028r9l"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "#",
      "/*qtype=search"
    ]
  },
  "elapsed_s": 26.2,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
