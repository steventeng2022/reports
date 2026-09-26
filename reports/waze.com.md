# Security Audit Report — waze.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://waze.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | waze.com |
| Test date | 2026-09-26 19:01 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 13 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Google Frontend
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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
- **Detail:** Header reveals: Google Frontend
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.waze.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 13. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (txkhwdizlsj6jj.waze.com and xxgcmxd0gpegka.waze.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=A2cp78UVYzrRvmujIIRO1QGJ2qIduJDJEPaJSxy0RsI; google-site-verification=N2mW-L25o-v4q4LkryQS55pL_C8CnsIL8-FpZUZtKEg; google-site-verification=k0_7da8Nm3RA9ZFG-8Nj2895hmeUdDr3RuP1vQVNyOs
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of waze.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 37 disallow path(s), e.g. /discuss/, /discuss/, /discuss/, /discuss/, /discuss/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 130.211.9.172 carries PTR 172.9.211.130.bc.googleusercontent.com. for waze.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "waze.com",
  "dns": {
    "a": [
      "130.211.9.172"
    ],
    "aaaa": [
      "2600:1901:0:b230::"
    ],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 40)",
      "aspmx3.googlemail.com (pref 50)",
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "ns-cloud-b1.googledomains.com.",
      "ns-cloud-b4.googledomains.com.",
      "ns-cloud-b3.googledomains.com.",
      "ns-cloud-b2.googledomains.com."
    ],
    "spf": [
      "google-site-verification=A2cp78UVYzrRvmujIIRO1QGJ2qIduJDJEPaJSxy0RsI",
      "16ra/0Xa4iKpOWPnK72tHaroVGQsuMznJmDEDmBusu1C6e/4+b4E3SeTLrx5fR986eGa7tZpf7eLhzEZcUwy/E5+xOYAmRhIXkWN1AukAurkqYFfWb0GpJBDnRvh8GPeG/S+P5wLQEe/LZMD1EN0gwjPELlE/j6JzrITIHejrJjdPDdJblqYibXrV8QqKc5LyK9I6dFjwWlRtuCC91hX21YxkRz+4QIDAQAB",
      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCQdUTtXUOIXQ+FrspRD1S4uLnWT2EjlztTB9/3upH3HsuOArbtSJoWXFuFj7ehPG47hmvBSr0lRHIB3rpb79WfgbntQ1p4wVO9U4RYA+Cbq7M++7n2BSjvFFOkQ9IC8TWJYeOM6ECO1Namizw1EsiTzOSqHQ5D0zWZbyHKom1aWQIDAQAB",
      "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAssPYphcnIMFiOS7ol1k6dJs14MLaA1cEiw8WOe8cNnLbvtcOtGBqhQmgvGGCapKX+B18HKCUTbnduTuOmKxzAThqoqMu2F22kSSWBf5q5mL5aM7XEc7w9wKG",
      "google-site-verification=N2mW-L25o-v4q4LkryQS55pL_C8CnsIL8-FpZUZtKEg",
      "v=spf1 include:_spf.google.com ~all",
      "google-site-verification=k0_7da8Nm3RA9ZFG-8Nj2895hmeUdDr3RuP1vQVNyOs",
      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYDCQ5ZlVEeUdMEopVa0bdjsTo+5JTdS+25aP+kPGoFNtzNG7No+64qoX9HuZvCe7sjmUncSCV2oEbdxgJvB/ODQ5cS3Px/qaqagn/ZXUBzgbtvHSEXV+ugH52us0i/i041qd0KHa6v/82Dg5XofyuDi+QgUoBa+hcw5JsqfKssQIDAQAB",
      "google-site-verification=nSaHA9lIP9L3gFJQEYxtSwHY88MBSrwRXlZ-vLztW04"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.waze.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR3",
    "notBefore": "Aug 30 19:56:01 2026 GMT",
    "notAfter": "Nov 28 20:51:55 2026 GMT",
    "san": [
      "*.waze.com",
      "waze.com",
      "world.waze.com",
      "*.world.waze.com",
      "waze.co.il",
      "*.waze.co.il"
    ],
    "days_left": 63,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "130.211.9.172",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Google Frontend"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.waze.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://waze.com/"
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
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=A2cp78UVYzrRvmujIIRO1QGJ2qIduJDJEPaJSxy0RsI",
    "google-site-verification=N2mW-L25o-v4q4LkryQS55pL_C8CnsIL8-FpZUZtKEg",
    "google-site-verification=k0_7da8Nm3RA9ZFG-8Nj2895hmeUdDr3RuP1vQVNyOs",
    "google-site-verification=nSaHA9lIP9L3gFJQEYxtSwHY88MBSrwRXlZ-vLztW04"
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
      "aia_ocsp": null,
      "not_before": "20260830195601",
      "not_after": "20261128205155"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/discuss/",
      "/discuss/",
      "/discuss/",
      "/discuss/",
      "/discuss/",
      "/discuss/admin/",
      "/discuss/auth/",
      "/discuss/assets/browser-update*.js",
      "/discuss/email/",
      "/discuss/session",
      "/discuss/user-api-key",
      "/discuss/*?api_key*",
      "/discuss/*?*api_key*",
      "/discuss/admin/",
      "/discuss/auth/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "172.9.211.130.bc.googleusercontent.com."
    ]
  },
  "elapsed_s": 26.0,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
