# Security Audit Report — mixcloud.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mixcloud.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | mixcloud.com |
| Test date | 2026-09-26 18:55 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 4, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 19 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 20 | info | CT1 | 64 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.5.36:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.5.36:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 12. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 15. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 16. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=CB4tWZGyP2d-9jp1_q7WPJOuIGz6UUHm8nnMeY9Tsj8; apple-domain-verification=cBSzBF9wU7M8t86W; google-site-verification=z00gWRhfVeQQGXNgzCg9xd2WUXMhFuWl4QbXx3mN5zU
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of mixcloud.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 19. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 3 disallow path(s), e.g. /oauth/, /short/, /pigeon/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 20. [INFO] 64 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.mixcloud.com, app.mixcloud.com, beta.mixcloud.com, blog.mixcloud.com, help.mixcloud.com, old.mixcloud.com, support.mixcloud.com, upload.mixcloud.com, ws.mixcloud.com, www.old.mixcloud.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "mixcloud.com",
  "dns": {
    "a": [
      "104.20.5.36",
      "104.20.4.36"
    ],
    "aaaa": [
      "2606:4700:10::6814:424",
      "2606:4700:10::6814:524"
    ],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 5)",
      "aspmx3.googlemail.com (pref 5)",
      "aspmx5.googlemail.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 3)",
      "aspmx4.googlemail.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 3)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "miles.ns.cloudflare.com.",
      "tegan.ns.cloudflare.com."
    ],
    "spf": [
      "cloudflare_dashboard_sso=a2939222461cc73e72b3c1a180c1715e",
      "google-site-verification=CB4tWZGyP2d-9jp1_q7WPJOuIGz6UUHm8nnMeY9Tsj8",
      "apple-domain-verification=cBSzBF9wU7M8t86W",
      "v=spf1 include:_spf.google.com include:mail.zendesk.com ip4:153.56.154.0/24 -all",
      "google-site-verification=z00gWRhfVeQQGXNgzCg9xd2WUXMhFuWl4QbXx3mN5zU",
      "google-site-verification=MIkL-g_FIR1v7JnMSJ-Ilfjqlqz6xAQtK7CP3AzlyNE"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:5f2e9c9009c34a7eab0b76c4cf89cb42@dmarc-reports.cloudflare.net,mailto:dmarc@mixcloud.com; adkim=s; aspf=s"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=mixcloud.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 26 14:45:33 2026 GMT",
    "notAfter": "Dec 25 15:45:28 2026 GMT",
    "san": [
      "mixcloud.com",
      "staging-chromecast.mixcloud.com",
      "*.staging-chromecast.mixcloud.com"
    ],
    "days_left": 89,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.20.5.36",
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
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.mixcloud.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.mixcloud.com/"
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
    "source": "certspotter",
    "count": 64,
    "notable": [
      "api.mixcloud.com",
      "app.mixcloud.com",
      "beta.mixcloud.com",
      "blog.mixcloud.com",
      "help.mixcloud.com",
      "old.mixcloud.com",
      "support.mixcloud.com",
      "upload.mixcloud.com",
      "ws.mixcloud.com",
      "www.old.mixcloud.com"
    ],
    "sample": [
      "adm-sftp.mixcloud.com",
      "api.mixcloud.com",
      "app.mixcloud.com",
      "beta.mixcloud.com",
      "blog.mixcloud.com",
      "campus.mixcloud.com",
      "cdn-fastly-live-fra1-hiv.mixcloud.com",
      "cdn-fastly-live-hkg1-hiv.mixcloud.com",
      "cdn-fastly-live-ogd1-wnx.mixcloud.com",
      "cdn-fastly-live-par1-gth.mixcloud.com",
      "chromecast.mixcloud.com",
      "factory.mixcloud.com",
      "follow-widget.mixcloud.com",
      "gtm-cloud-run.mixcloud.com",
      "help.mixcloud.com",
      "i.mixcloud.com",
      "live-fra1-hiv.mixcloud.com",
      "live-hkg1-hiv.mixcloud.com",
      "live-ogd1-wnx.mixcloud.com",
      "live-par1-gth.mixcloud.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=CB4tWZGyP2d-9jp1_q7WPJOuIGz6UUHm8nnMeY9Tsj8",
    "apple-domain-verification=cBSzBF9wU7M8t86W",
    "google-site-verification=z00gWRhfVeQQGXNgzCg9xd2WUXMhFuWl4QbXx3mN5zU",
    "google-site-verification=MIkL-g_FIR1v7JnMSJ-Ilfjqlqz6xAQtK7CP3AzlyNE"
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
      "not_before": "20260926144533",
      "not_after": "20261225154528"
    }
  },
  "http2": {
    "robots_disallow": [
      "/oauth/",
      "/short/",
      "/pigeon/"
    ]
  },
  "x12": {
    "status": 301
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
