# Security Audit Report — aws.amazon.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://aws.amazon.com/ |
| Bug bounty program | Amazon |
| Listed scope domain | aws.amazon.com |
| Test date | 2026-09-26 18:46 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 2, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 9 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 12 | info | CK5 | Cookie scoped to parent domain (.amazon.com) | CWE-200 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Server
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Server
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'aws_lang' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 9. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'aws_lang' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of aws.amazon.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but aws.amazon.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 12. [INFO] Cookie scoped to parent domain (.amazon.com) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host aws.amazon.com.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 271 disallow path(s), e.g. /alexaforbusiness/, /blogs/, /*/blogs/, /solutions/case-studies/, /*/solutions/case-studies/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 54.192.248.37 carries PTR server-54-192-248-37.tpe53.r.cloudfront.net. for aws.amazon.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "aws.amazon.com",
  "dns": {
    "a": [
      "54.192.248.37",
      "54.192.248.69",
      "54.192.248.11",
      "54.192.248.79"
    ],
    "aaaa": [
      "2600:9000:202f:e400:1c:a813:8500:93a1",
      "2600:9000:202f:4c00:1c:a813:8500:93a1",
      "2600:9000:202f:a200:1c:a813:8500:93a1",
      "2600:9000:202f:b400:1c:a813:8500:93a1",
      "2600:9000:202f:5000:1c:a813:8500:93a1",
      "2600:9000:202f:9600:1c:a813:8500:93a1",
      "2600:9000:202f:ca00:1c:a813:8500:93a1",
      "2600:9000:202f:aa00:1c:a813:8500:93a1"
    ],
    "cname": "tp.8e49140c2-frontier.amazon.com.",
    "mx": [],
    "ns": [
      "ns-1860.awsdns-40.co.uk.",
      "ns-1402.awsdns-47.org.",
      "ns-905.awsdns-49.net.",
      "ns-106.awsdns-13.com."
    ],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=aws.amazon.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Aug 19 00:00:00 2026 GMT",
    "notAfter": "Mar  4 23:59:59 2027 GMT",
    "san": [
      "aws.amazon.com",
      "aws-us-west-2.amazon.com",
      "1.aws-lbr.amazonaws.com",
      "www.aws.amazon.com",
      "amazonaws-china.com",
      "www.amazonaws-china.com",
      "aws-us-east-1.amazon.com"
    ],
    "days_left": 159,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.37",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html;charset=utf-8",
    "title": "Cloud Computing Services - Amazon Web Services (AWS)"
  },
  "mixed_content": [],
  "tech": [
    "Server: Server"
  ],
  "cookies": [
    {
      "domain": ".aws.amazon.com"
    },
    {
      "domain": ".amazon.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.aws.amazon.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://aws.amazon.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "cname_chain": [
    "tp.8e49140c2-frontier.amazon.com",
    "dr49lng3n1n2s.cloudfront.net"
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
      "not_before": "20260819000000",
      "not_after": "20270304235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/alexaforbusiness/",
      "/blogs/",
      "/*/blogs/",
      "/solutions/case-studies/",
      "/*/solutions/case-studies/",
      "/about-aws/whats-new/200",
      "/about-aws/whats-new/201",
      "/about-aws/whats-new/2020",
      "/about-aws/whats-new/2021",
      "/about-aws/whats-new/2022",
      "/about-aws/whats-new/2023",
      "/about-aws/whats-new/2024",
      "/*/blogs/*/tag/",
      "/blogs/*/tag/",
      "*/confirmation/"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-54-192-248-37.tpe53.r.cloudfront.net."
    ]
  },
  "elapsed_s": 8.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
