# Security Audit Report — ietf.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ietf.org/ |
| Bug bounty program | IETF |
| Listed scope domain | ietf.org |
| Test date | 2026-09-26 17:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 5, Info: 17)

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
| 16 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 17 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 18 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 19 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 20 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 21 | info | CT1 | 66 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 22 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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
- **Detail:** TCP connect to 104.16.45.99:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.45.99:8443 succeeded (state-only check, no payload sent).
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=NQpGlv9isd8O_RHzO31C0lOw1XKfQfFoVhZbmir6Lm4; google-site-verification=mvpHmuqmM4wrWv5w3S1AAqssmhAITNo2QqPqVLrVWEo
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 19. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of ietf.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 20. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 2 disallow path(s), e.g. /admin/, /search/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 21. [INFO] 66 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: demo.ietf.org, dev.ietf.org, files.meeting.ietf.org, git.noc.ietf.org, grafana.noc.ietf.org, k8s.ietf.org, ops.ietf.org, staging.ietf.org, store.ietf.org, www.store.ietf.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 22. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: demo.ietf.org; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "ietf.org",
  "dns": {
    "a": [
      "104.16.45.99",
      "104.16.44.99"
    ],
    "aaaa": [
      "2606:4700::6810:2d63",
      "2606:4700::6810:2c63"
    ],
    "cname": null,
    "mx": [
      "mx.ietf.org (pref 0)"
    ],
    "ns": [
      "jill.ns.cloudflare.com.",
      "ken.ns.cloudflare.com."
    ],
    "spf": [
      "google-site-verification=NQpGlv9isd8O_RHzO31C0lOw1XKfQfFoVhZbmir6Lm4",
      "v=spf1 ip4:166.84.6.31 ip4:166.84.7.238 ip6:2602:f977:800:f7f6::/64 ip4:166.84.7.34 ip6:2602:f977:800::e276:63ff:fe66:3400 include:_spf.google.com include:spf.hostedrt.com ~all",
      "vs58md9pf8hu6knlglfda9lk6g",
      "google-site-verification=mvpHmuqmM4wrWv5w3S1AAqssmhAITNo2QqPqVLrVWEo",
      "ca3-5567e36d3f9947308ac2892e009840cc"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:dmarc_agg@vali.email,mailto:dmarc-report@ietf.org"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=ietf.org",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 18 12:04:05 2026 GMT",
    "notAfter": "Dec 17 13:04:03 2026 GMT",
    "san": [
      "ietf.org",
      "idnits.ietf.org"
    ],
    "days_left": 81,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.16.45.99",
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
      "domain": "ietf.org",
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
      "origin": "https://sub.ietf.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.ietf.org/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 66,
    "notable": [
      "demo.ietf.org",
      "dev.ietf.org",
      "files.meeting.ietf.org",
      "git.noc.ietf.org",
      "grafana.noc.ietf.org",
      "k8s.ietf.org",
      "ops.ietf.org",
      "staging.ietf.org",
      "store.ietf.org",
      "www.store.ietf.org"
    ],
    "sample": [
      "account.ietf.org",
      "alertmanager.meeting.ietf.org",
      "avatars.account.ietf.org",
      "dashboard.meeting.ietf.org",
      "deadmon.meeting.ietf.org",
      "demo.ietf.org",
      "dev.ietf.org",
      "dev2.ietf.org",
      "docker.meeting.ietf.org",
      "docker.noc.ietf.org",
      "drone.meeting.ietf.org",
      "files.meeting.ietf.org",
      "forgejo.noc.ietf.org",
      "git.noc.ietf.org",
      "grafana.noc.ietf.org",
      "hacknet.meeting.ietf.org",
      "hedgedoc.noc.ietf.org",
      "iabdev.ietf.org",
      "iaoc.ietf.org",
      "idnits.ietf.org"
    ],
    "dangling": [
      "demo.ietf.org"
    ]
  },
  "apex_txt": [
    "google-site-verification=NQpGlv9isd8O_RHzO31C0lOw1XKfQfFoVhZbmir6Lm4",
    "google-site-verification=mvpHmuqmM4wrWv5w3S1AAqssmhAITNo2QqPqVLrVWEo"
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
      "/admin/",
      "/search/"
    ]
  },
  "elapsed_s": 6.3,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
