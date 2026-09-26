# Security Audit Report — blogs.scientificamerican.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blogs.scientificamerican.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | blogs.scientificamerican.com |
| Test date | 2026-09-26 21:59 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 1, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | info | H6 | Server technology disclosure | CWE-200 |
| 5 | info | P8 | Missing security.txt | CWE-1038 |
| 6 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 7 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 8 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 9 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 10 | low | RD2 | HTTPS root redirects to a different domain | CWE-200 |
| 11 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 5. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 6. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m01.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 7. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but blogs.scientificamerican.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 8. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://blogs.scientificamerican.com/ carries Cache-Control: max-age=0; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 9. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 65.9.180.86 carries PTR server-65-9-180-86.tpe53.r.cloudfront.net. for blogs.scientificamerican.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 10. [LOW] HTTPS root redirects to a different domain (`RD2`)

- **CWE:** CWE-200
- **Detail:** https://blogs.scientificamerican.com/ answered 302 with Location: https://www.scientificamerican.com/ (cross-domain handoff at the entry point).
- **Recommendation:** Review the cross-domain redirect; it discloses the real entry point and can be abused in open-redirect-style flows.

### 11. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for blogs.scientificamerican.com; apex scientificamerican.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

## Evidence (raw response observations)

```json
{
  "domain": "blogs.scientificamerican.com",
  "dns": {
    "a": [
      "65.9.180.86",
      "65.9.180.98",
      "65.9.180.96",
      "65.9.180.72"
    ],
    "aaaa": [
      "2600:9000:202b:7e00:12:7409:4340:93a1",
      "2600:9000:202b:200:12:7409:4340:93a1",
      "2600:9000:202b:fa00:12:7409:4340:93a1",
      "2600:9000:202b:a000:12:7409:4340:93a1",
      "2600:9000:202b:5200:12:7409:4340:93a1",
      "2600:9000:202b:1400:12:7409:4340:93a1",
      "2600:9000:202b:6800:12:7409:4340:93a1",
      "2600:9000:202b:c800:12:7409:4340:93a1"
    ],
    "cname": null,
    "mx": [],
    "ns": [],
    "caa": [],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=scientificamerican.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "May 26 00:00:00 2026 GMT",
    "notAfter": "Dec  9 23:59:59 2026 GMT",
    "san": [
      "scientificamerican.com",
      "*.sciam.com",
      "sciam.com",
      "*.scientificamerican.com"
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
    "ip": "65.9.180.86",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.blogs.scientificamerican.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://blogs.scientificamerican.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 403,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "source": "certspotter",
    "count": 0,
    "notable": [],
    "sample": []
  },
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": "http://ocsp.r2m01.amazontrust.com",
      "not_before": "20260526000000",
      "not_after": "20261209235959"
    },
    "ocsp": "http-403"
  },
  "x12": {
    "status": 302,
    "ptr": [
      "server-65-9-180-86.tpe53.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 302,
    "root_location": "https://www.scientificamerican.com/",
    "http_status": 301,
    "p404_status": 302,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 5.4,
  "rechecked": "2026-09-26 21:56 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- Findings are reported against the public program scope; submission through the program tracker is pending.
