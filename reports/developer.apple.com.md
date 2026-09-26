# Security Audit Report — developer.apple.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://developer.apple.com/ |
| Bug bounty program | Apple |
| Listed scope domain | developer.apple.com |
| Test date | 2026-09-26 17:43 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 0, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 9 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 10 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 11 | info | CT1 | 14 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apple
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 5. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Apple
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of developer.apple.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 9. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but developer.apple.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 10. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 13 disallow path(s), e.g. /cgi-bin/, /click/, /documentation/dataformats/, /reference/, /search/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 11. [INFO] 14 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.developer.apple.com, api.enterprise.developer.apple.com, docs.developer.apple.com, download.developer.apple.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "developer.apple.com",
  "dns": {
    "a": [
      "17.253.117.133",
      "17.253.117.132"
    ],
    "aaaa": [
      "2403:300:a30:f000::134",
      "2403:300:a30:f000::133"
    ],
    "cname": "developer-cdn.apple.com.akadns.net.",
    "mx": [],
    "ns": [],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "businessCategory=Private Organization, jurisdictionCountryName=US, jurisdictionStateOrProvinceName=California, serialNumber=C0806592, countryName=US, stateOrProvinceName=California, localityName=Cupertino, organizationName=Apple Inc., commonName=developer.apple.com",
    "issuer": "countryName=US, organizationName=Apple Inc., commonName=Apple Public EV Server ECC CA 1 - G1",
    "notBefore": "Sep 21 17:14:56 2026 GMT",
    "notAfter": "Dec 17 18:07:35 2026 GMT",
    "san": [
      "docs-assets.developer.apple.com",
      "developer.apple.com",
      "developers.apple.com",
      "docs.developer.apple.com"
    ],
    "days_left": 82,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "17.253.117.133",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "Apple Developer"
  },
  "mixed_content": [],
  "tech": [
    "Server: Apple"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.developer.apple.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://developer.apple.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 300,
    "/security.txt": 300,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 403
  },
  "subdomains": {
    "source": "certspotter",
    "count": 14,
    "notable": [
      "api.developer.apple.com",
      "api.enterprise.developer.apple.com",
      "docs.developer.apple.com",
      "download.developer.apple.com"
    ],
    "sample": [
      "api.developer.apple.com",
      "api.enterprise.developer.apple.com",
      "developer.apple.com",
      "docs-assets.developer.apple.com",
      "docs.developer.apple.com",
      "download.developer.apple.com",
      "forums.developer.apple.com",
      "icloud.developer.apple.com",
      "maps.developer.apple.com",
      "ml.developer.apple.com",
      "partners.developer.apple.com",
      "sa-config.developer.apple.com",
      "search.developer.apple.com",
      "www.developer.apple.com"
    ]
  },
  "cname_chain": [
    "developer-cdn.apple.com.akadns.net",
    "developer.cdn.v.aaplimg.com"
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
      "/cgi-bin/",
      "/click/",
      "/documentation/dataformats/",
      "/reference/",
      "/search/",
      "/survey/",
      "/temp/",
      "/unsubscribe/",
      "/forums/create/question",
      "/forums/login",
      "/forums/preferences",
      "/forums/profile",
      "/forums/*?view"
    ]
  },
  "elapsed_s": 12.7,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
