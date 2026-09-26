# Security Audit Report — in.linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://in.linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | in.linkedin.com |
| Test date | 2026-09-26 17:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 1, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 12 | info | CK5 | Cookie scoped to parent domain (.linkedin.com) | CWE-200 |
| 13 | low | CK4 | Session-like cookie without HttpOnly | CWE-1004 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | CT1 | 1 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.41.41:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.41.41:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Java session cookie (J2EE); Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of in.linkedin.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but in.linkedin.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 12. [INFO] Cookie scoped to parent domain (.linkedin.com) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host in.linkedin.com.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 13. [LOW] Session-like cookie without HttpOnly (`CK4`)

- **CWE:** CWE-1004
- **Detail:** Cookie 'JSESSIONID' looks session-related and has no HttpOnly attribute.
- **Recommendation:** Set HttpOnly on session cookies.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 4398 disallow path(s), e.g. /addContacts*, /addressBookExport*, /ambry, /analytics/, /answers*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] 1 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "in.linkedin.com",
  "dns": {
    "a": [
      "104.18.41.41",
      "172.64.146.215"
    ],
    "aaaa": [
      "2600:1901:0:d5ad::"
    ],
    "cname": "cctld.linkedin.com.",
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
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Sunnyvale, organizationName=Linkedin Corporation, commonName=ep.linkedin.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Sep  3 00:00:00 2026 GMT",
    "notAfter": "Mar  3 23:59:59 2027 GMT",
    "san": [
      "ep.linkedin.com",
      "er.linkedin.com",
      "es.linkedin.com",
      "et.linkedin.com",
      "eu.linkedin.com",
      "ev.linkedin.com",
      "ew.linkedin.com",
      "fi.linkedin.com",
      "fj.linkedin.com",
      "fk.linkedin.com",
      "fl.linkedin.com",
      "fm.linkedin.com",
      "fo.linkedin.com",
      "fq.linkedin.com",
      "fr.linkedin.com",
      "fx.linkedin.com",
      "ga.linkedin.com",
      "gb.linkedin.com",
      "gc.linkedin.com",
      "gd.linkedin.com",
      "ge.linkedin.com",
      "gf.linkedin.com",
      "gg.linkedin.com",
      "gh.linkedin.com",
      "gi.linkedin.com",
      "gl.linkedin.com",
      "gm.linkedin.com",
      "gn.linkedin.com",
      "gp.linkedin.com",
      "gq.linkedin.com",
      "gr.linkedin.com",
      "gs.linkedin.com",
      "gt.linkedin.com",
      "gu.linkedin.com",
      "gw.linkedin.com",
      "gy.linkedin.com",
      "hk.linkedin.com",
      "hm.linkedin.com",
      "hn.linkedin.com",
      "hr.linkedin.com",
      "ht.linkedin.com",
      "hu.linkedin.com",
      "hv.linkedin.com",
      "ib.linkedin.com",
      "ic.linkedin.com",
      "id.linkedin.com",
      "ie.linkedin.com",
      "il.linkedin.com",
      "im.linkedin.com",
      "in.linkedin.com",
      "io.linkedin.com",
      "iq.linkedin.com",
      "ir.linkedin.com",
      "is.linkedin.com",
      "it.linkedin.com",
      "ja.linkedin.com",
      "je.linkedin.com",
      "jm.linkedin.com",
      "jo.linkedin.com",
      "jp.linkedin.com",
      "jt.linkedin.com",
      "ke.linkedin.com",
      "kg.linkedin.com",
      "kh.linkedin.com",
      "ki.linkedin.com",
      "km.linkedin.com",
      "kn.linkedin.com",
      "kp.linkedin.com",
      "kr.linkedin.com",
      "kw.linkedin.com",
      "ky.linkedin.com",
      "kz.linkedin.com",
      "la.linkedin.com",
      "lb.linkedin.com",
      "lc.linkedin.com",
      "lf.linkedin.com",
      "li.linkedin.com"
    ],
    "days_left": 158,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.41.41",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "LinkedIn India: Log In or Sign Up"
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Java session cookie (J2EE)",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": ".in.linkedin.com",
      "samesite": "none"
    },
    {
      "domain": "linkedin.com",
      "samesite": "none"
    },
    {
      "domain": ".linkedin.com",
      "samesite": "none"
    },
    {
      "domain": ".in.linkedin.com",
      "samesite": "none"
    },
    {
      "domain": ".linkedin.com",
      "samesite": "none"
    },
    {
      "domain": "linkedin.com",
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
      "origin": "https://sub.in.linkedin.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://in.linkedin.com/hp"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 400",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
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
    "source": "crt.sh",
    "count": 1,
    "notable": [],
    "sample": [
      "in.linkedin.com"
    ]
  },
  "cname_chain": [
    "cctld.linkedin.com",
    "cctld.es.lnkdns.net",
    "www.linkedin.com.cdn.cloudflare.net"
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
      "/addContacts*",
      "/addressBookExport*",
      "/ambry",
      "/analytics/",
      "/answers*",
      "/authwall",
      "/badges/profile/create",
      "/cap/",
      "/chat/",
      "/checkpoint/",
      "/companyDir*",
      "/connections*",
      "/csp/",
      "/e/",
      "/edurec*"
    ]
  },
  "elapsed_s": 12.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
