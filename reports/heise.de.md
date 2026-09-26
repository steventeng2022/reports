# Security Audit Report — heise.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://heise.de/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | heise.de |
| Test date | 2026-09-26 17:46 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | MAIL10 | DMARC subdomain policy (sp=) set while apex policy is p=none | CWE-285 |
| 14 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 15 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 16 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 17 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 18 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=604800 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [INFO] DMARC subdomain policy (sp=) set while apex policy is p=none (`MAIL10`)

- **CWE:** CWE-285
- **Detail:** Subdomains are enforced while the apex domain is monitor-only.
- **Recommendation:** Confirm the split policy is intended.

### 14. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 15. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 16. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=8kcKAZp-IbbJG7FQzRxIaUXv9Ku4qX0wgMrm_hx_L2s; tollbit-domain-verification=6fd594c990db1742b6cb34f3699d3944885e664c32333cf8cb17; google-site-verification=7CvE9FRS3zv0wnl8KzLmVw0TSlQay6qOX_zGFm2wzWw
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 17. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of heise.de has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 18. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but heise.de is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

## Evidence (raw response observations)

```json
{
  "domain": "heise.de",
  "dns": {
    "a": [
      "193.99.144.80"
    ],
    "aaaa": [
      "2a02:2e0:3fe:1001:302::"
    ],
    "cname": null,
    "mx": [
      "mx04.hornetsecurity.com (pref 40)",
      "mx01.hornetsecurity.com (pref 10)",
      "mx02.hornetsecurity.com (pref 20)",
      "mx03.hornetsecurity.com (pref 30)"
    ],
    "ns": [
      "ns.plusline.de.",
      "ns.heise.de.",
      "ns2.pop-hannover.net.",
      "ns.s.plusline.de.",
      "ns.pop-hannover.de."
    ],
    "spf": [
      "brevo-code:e09d9e43d8e705fdcf03fb07346ec6f5",
      "c3ViZG9tYWlu",
      "google-site-verification=8kcKAZp-IbbJG7FQzRxIaUXv9Ku4qX0wgMrm_hx_L2s",
      "kT2+bTXGMSIudHQATflucV7vjLhdq9Y18pKTKJxs0O2IebE8seBu4vCAe9MBHYehuRJWwKKt1klytxF4vyuSpA==",
      "v=spf1 ip4:193.99.144.0/24 ip4:193.99.145.0/24 ip6:2a02:2e0:3fe:1001::/64 ip6:2a00:e68:14:800::/64 ip4:193.100.232.56 ip6:2a00:e68:14:801:bad::beef include:_spfdiv.heise.de include:spf.dsb.net include:spf.hornetsecurity.com ~all",
      "tollbit-domain-verification=6fd594c990db1742b6cb34f3699d3944885e664c32333cf8cb176da9aac3ab71",
      "google-site-verification=7CvE9FRS3zv0wnl8KzLmVw0TSlQay6qOX_zGFm2wzWw",
      "docusign=b14b0107-39e4-44c2-b48f-944859786474",
      "wUIdRqARf1uNkZkPoWGdYvEmK408vvKC3HKme1h/rnswYDphj9Ytgwt6K1Df1PQnW64Oi3t9c9uKoo989wv8xw==",
      "apple-domain-verification=m53iQZB4O1uMxDGR",
      "miro-verification=601d1e3e9623fe2102de9d6d215a2380ae5c69bd"
    ],
    "dmarc": [
      "v=DMARC1; p=none; sp=none; rua=mailto:dmarc.report@heise.de"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=heise.de",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Sep  2 22:23:04 2026 GMT",
    "notAfter": "Dec  1 22:23:03 2026 GMT",
    "san": [
      "heise.de"
    ],
    "days_left": 66,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "193.99.144.80",
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
      "origin": "https://sub.heise.de",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.heise.de/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 410,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 404,
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
    "google-site-verification=8kcKAZp-IbbJG7FQzRxIaUXv9Ku4qX0wgMrm_hx_L2s",
    "tollbit-domain-verification=6fd594c990db1742b6cb34f3699d3944885e664c32333cf8cb17",
    "google-site-verification=7CvE9FRS3zv0wnl8KzLmVw0TSlQay6qOX_zGFm2wzWw",
    "apple-domain-verification=m53iQZB4O1uMxDGR",
    "miro-verification=601d1e3e9623fe2102de9d6d215a2380ae5c69bd"
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
  "elapsed_s": 30.9,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
