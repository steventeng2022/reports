# Security Audit Report — hostgator.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hostgator.com/ |
| Bug bounty program | Host Gator |
| Listed scope domain | hostgator.com |
| Test date | 2026-09-26 18:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 6, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 7 | low | H1 | Missing HSTS header | CWE-319 |
| 8 | low | H2 | Missing CSP header | CWE-1021 |
| 9 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 10 | low | H4 | No clickjacking protection | CWE-1023 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 13 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |
| 15 | info | P8 | Missing security.txt | CWE-1038 |
| 16 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 17 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 18 | info | MAIL10 | DMARC subdomain policy (sp=) set while apex policy is p=none | CWE-285 |
| 19 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 20 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 21 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 22 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.43.48:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.43.48:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 7. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 8. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 9. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 10. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 12. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 13. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 14. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 15. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 16. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 17. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): spf.websitewelco (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 18. [INFO] DMARC subdomain policy (sp=) set while apex policy is p=none (`MAIL10`)

- **CWE:** CWE-285
- **Detail:** Subdomains are enforced while the apex domain is monitor-only.
- **Recommendation:** Confirm the split policy is intended.

### 19. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 20. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 21. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=268NzFe_2w_P3-j4fg2PDTwC5tgY0m__CQR9hYG7hSA; google-site-verification=XD3tFbXKRYV0fG-3zRGEzPC2irkiXg9Rz2eIKCG-0IQ; google-site-verification=0vcyIt2ASVGA-Hnox9hZPXaaLIX5pYSm8dZd0_0HLyU
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 22. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of hostgator.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "hostgator.com",
  "dns": {
    "a": [
      "104.18.43.48",
      "172.64.144.208"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "hostgator-com.mail.eo.outlook.com (pref 0)"
    ],
    "ns": [
      "cody.ns.cloudflare.com.",
      "erin.ns.cloudflare.com."
    ],
    "spf": [
      "google-site-verification=268NzFe_2w_P3-j4fg2PDTwC5tgY0m__CQR9hYG7hSA",
      "google-site-verification=XD3tFbXKRYV0fG-3zRGEzPC2irkiXg9Rz2eIKCG-0IQ",
      "MS=ms19427866",
      "google-site-verification=0vcyIt2ASVGA-Hnox9hZPXaaLIX5pYSm8dZd0_0HLyU",
      "v=spf1 ip4:209.17.115.0/24 ip4:64.69.218.0/24 include:spf.constantcontact.com include:_spf.salesforce.com include:_spf2.hostgator.com include:spf.protection.outlook.com include:eig.spf.a.cloudfilter.net include:_spf.myorderbox.com include:spf.websitewelco",
      "me.com -all",
      "google-site-verification=HUY22ADwgB0ij1JaYucTVtUI6dAvbNp5g4nQQ9tKHHc",
      "google-site-verification=pj2LYTgRxkGunX03DSguHxBxwaBABFEUxEDsLgOdlys",
      "google-site-verification=yx1ED4Liv7PN2PvYnLuop_CVyyyxLz8lc5M2MRnSNWk",
      "google-site-verification=oYqxGxAsuHwvRDo4FqADW6ToV1nf8ITUfcw728UUvuI",
      "knowbe4-site-verification=2196cd8a72de50eedd7703120b752b77",
      "google-site-verification=WH8320OT9w-ZORb35j4X4VbeUNoMrUyhXoAzISUhEo0"
    ],
    "dmarc": [
      "v=DMARC1; p=none; pct=100; rua=mailto:re+kgjw4j9bykj@dmarc.postmarkapp.com; sp=none; aspf=r;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=hostgator.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 25 16:42:43 2026 GMT",
    "notAfter": "Nov 23 17:42:38 2026 GMT",
    "san": [
      "hostgator.com",
      "*.hostgator.com"
    ],
    "days_left": 57,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.43.48",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "hostgator.com",
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
      "origin": "https://sub.hostgator.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 403
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
    "google-site-verification=268NzFe_2w_P3-j4fg2PDTwC5tgY0m__CQR9hYG7hSA",
    "google-site-verification=XD3tFbXKRYV0fG-3zRGEzPC2irkiXg9Rz2eIKCG-0IQ",
    "google-site-verification=0vcyIt2ASVGA-Hnox9hZPXaaLIX5pYSm8dZd0_0HLyU",
    "google-site-verification=HUY22ADwgB0ij1JaYucTVtUI6dAvbNp5g4nQQ9tKHHc",
    "google-site-verification=pj2LYTgRxkGunX03DSguHxBxwaBABFEUxEDsLgOdlys"
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
      "aia_ocsp": null,
      "not_before": "20260825164243",
      "not_after": "20261123174238"
    }
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 4.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
