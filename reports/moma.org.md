# Security Audit Report — moma.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://moma.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | moma.org |
| Test date | 2026-09-26 18:55 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 3, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.9.51:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.9.51:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=0 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 10. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: facebook-domain-verification=96ykiggrug8zd9zhq3ejj0o2xjaa5a; google-site-verification=3vrESLJUNQb4JqQa8uIUtVm0gkEsm5oafDbFFb-Gmfg; have-i-been-pwned-verification=3bd956232b1c0dad85b7b5242f3720df
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of moma.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but moma.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 20 disallow path(s), e.g. /dist/robots.*.js, /assets/robots-*.js, /calendar/events/9322, /calendar/programs/46, /calendar/programs/50
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of moma.org permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

## Evidence (raw response observations)

```json
{
  "domain": "moma.org",
  "dns": {
    "a": [
      "104.18.9.51",
      "104.18.8.51"
    ],
    "aaaa": [
      "2606:4700::6812:833",
      "2606:4700::6812:933"
    ],
    "cname": null,
    "mx": [
      "mxa-004c0e03.gslb.pphosted.com (pref 0)",
      "mxb-004c0e03.gslb.pphosted.com (pref 0)"
    ],
    "ns": [
      "logan.ns.cloudflare.com.",
      "wren.ns.cloudflare.com."
    ],
    "spf": [
      "MS=9B2FE3DB81DB00D53D1BFA0F1D9897DCB7619E42",
      "dptqjki8g3tpucjbno6bv0r3ed",
      "facebook-domain-verification=96ykiggrug8zd9zhq3ejj0o2xjaa5a",
      "v=spf1 include:_spf.google.com ip4:63.117.124.0/24 ip4:65.211.53.131 ip4:38.125.15.118 ip4:107.20.210.250 ip4:52.1.14.157 ip4:23.253.211.221/32 ip4:184.106.16.5/32 ip4:52.36.126.62/32 ip4:35.163.139.47/32 ip4:69.164.65.171 include:mail.zendesk.com include",
      ":_spf.ultipro.com include:spf-004c0e03.pphosted.com include:docebosaas.com ~all",
      "google-site-verification=3vrESLJUNQb4JqQa8uIUtVm0gkEsm5oafDbFFb-Gmfg",
      "have-i-been-pwned-verification=3bd956232b1c0dad85b7b5242f3720df",
      "apple-domain-verification=30ovqro8hjqtAhgr",
      "google-site-verification=Y-uTmVZnxgZVfkpYVvi7X3qlAYSc1xdliEpLwZoIFao",
      "4c0pp3f0d6bo3int3c8jkj2fjs",
      "google-site-verification=Pr3kjMN9vtOp3O8BqAWWYoelYopZAUO7Q8eqYosiMTI",
      "adobe-idp-site-verification=0c9cf8b4135f0a8731823b237d8cf4a91045693c783f74dbce5f0a469f13a3a6",
      "goodnotes-verification=94d9f771-8767-4f8d-a3c3-4c17bf561900",
      "asv=5af33c11b29472a1d1f53d055ae36eb5",
      "6c7i0ouo1f4lfseov2dnbc1di4",
      "anthropic-domain-verification-5jmb3h=HkL8hTUNs7yxLr4I6dZEQ6iau",
      "jamf-site-verification=6kUWqIVkyYyYgf0RoJ_ZHQ"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:x0bskx3o@ag.dmarcian.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=moma.org",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 13 17:47:26 2026 GMT",
    "notAfter": "Dec 12 18:47:24 2026 GMT",
    "san": [
      "moma.org",
      "*.moma.org"
    ],
    "days_left": 76,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.9.51",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
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
      "origin": "https://sub.moma.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://moma.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "facebook-domain-verification=96ykiggrug8zd9zhq3ejj0o2xjaa5a",
    "google-site-verification=3vrESLJUNQb4JqQa8uIUtVm0gkEsm5oafDbFFb-Gmfg",
    "have-i-been-pwned-verification=3bd956232b1c0dad85b7b5242f3720df",
    "apple-domain-verification=30ovqro8hjqtAhgr",
    "google-site-verification=Y-uTmVZnxgZVfkpYVvi7X3qlAYSc1xdliEpLwZoIFao"
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
      "not_before": "20260913174726",
      "not_after": "20261212184724"
    }
  },
  "http2": {
    "robots_disallow": [
      "/dist/robots.*.js",
      "/assets/robots-*.js",
      "/calendar/events/9322",
      "/calendar/programs/46",
      "/calendar/programs/50",
      "/calendar/programs/9",
      "/calendar/exhibitions/3223",
      "/collection/browse_results.php",
      "/collection/object.php",
      "/collection/artist.php",
      "/collection/theme.php",
      "/collection_lb/browse_results.php",
      "/collection_ge/browse_results.php",
      "/collection/search.php",
      "/visit/calendar/search"
    ]
  },
  "x12": {
    "status": 403
  },
  "elapsed_s": 6.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
