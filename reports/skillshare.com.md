# Security Audit Report — skillshare.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://skillshare.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | skillshare.com |
| Test date | 2026-09-26 18:59 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 3, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | CT1 | 26 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 18 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.32.122:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.32.122:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: h1-domain-verification=J1qQPbBWpbBxGVL3i3h1dpw2rX1NwHEZhnWeRNNP5L9qB2DX; google-site-verification=DshzQEv8w03dqk3NErt1hlkBaXsKdTMaUfBY1J-8Wic; facebook-domain-verification=va9wk46fanagqpr4rc6sp4d3gap007
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of skillshare.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 11 disallow path(s), e.g. /site/search/, /dashboard/, /reset-password/, /mixpanel/, /search?
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] 26 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: auth.skillshare.com, cloudflare.ingress.ops.skillshare.com, dev.skillshare.com, eng.ops.skillshare.com, events.docs.internal.skillshare.com, help.skillshare.com, ops.skillshare.com, prod.atlas.blog.skillshare.com, stg.atlas.blog.skillshare.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 18. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: dev.skillshare.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "skillshare.com",
  "dns": {
    "a": [
      "104.18.32.122",
      "172.64.155.134"
    ],
    "aaaa": [
      "2a06:98c1:310c::6812:207a",
      "2606:4700:440b::ac40:9b86"
    ],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 40)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)",
      "aspmx4.googlemail.com (pref 50)",
      "aspmx3.googlemail.com (pref 50)",
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx5.googlemail.com (pref 50)"
    ],
    "ns": [
      "garen.skillshare.com.",
      "ashe.skillshare.com."
    ],
    "spf": [
      "amazonses:FA3mpwGhZzBmEIrp3iQXIXa3+umrH8ce03vBPry8tuI=",
      "h1-domain-verification=J1qQPbBWpbBxGVL3i3h1dpw2rX1NwHEZhnWeRNNP5L9qB2DX",
      "google-site-verification=DshzQEv8w03dqk3NErt1hlkBaXsKdTMaUfBY1J-8Wic",
      "facebook-domain-verification=va9wk46fanagqpr4rc6sp4d3gap007",
      "anthropic-domain-verification-0j2hh2=VDsV2bFDu3c0IZWFsXlG1WQ4h",
      "jamf-site-verification=jsRO5e76-EWTHTbtESgo9g",
      "9p1q7gjsjf6jgqmkdvbdxhxch33lxzsv",
      "mixpanel-domain-verify=739bd2fb-b682-4acf-9689-e94b74a61621",
      "miro-verification=2accb01b1b638f37ee0cd64452e2faaa57e1cdf6",
      "google-site-verification=mcHpWbpzXVe4BOFgp5ijuXXqIf7OMoH1Z7ctm2mlBDc",
      "apple-domain-verification=Hb38JzhNUvqf3hR2",
      "qyylpgj14chmtmds8wgz7j8lqwrd44tt",
      "v=spf1 include:_spf0.skillshare.com include:_spf1.skillshare.com include:_spf2.skillshare.com include:_spf3.skillshare.com include:sendgrid.net include:_spf.google.com include:sendgrid.net include:_spf.google.com ip4:23.21.109.197 ip4:23.21.109.212 ~all",
      "firebase=skillshare-creator-dev",
      "atlassian-domain-verification=caa1SXVOa/jn5JVpUdP/OCpP1t9l1rz9ikhEsdPLJYGgYWquY6v2tDOvBhNoJG99",
      "openai-domain-verification=dv-98OuGQNGSB3R75FCYqMmzHqw",
      "fw8mkvj2p2lgsk7crsrgylmvpzf0fkkw"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:f4a1b21ad84d418380c0e4bd42294746@dmarc-reports.cloudflare.net; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=skillshare.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 19 16:07:16 2026 GMT",
    "notAfter": "Nov 17 17:07:13 2026 GMT",
    "san": [
      "skillshare.com",
      "phoenix-demo.skillshare.com",
      "*.phoenix-demo.skillshare.com"
    ],
    "days_left": 51,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.32.122",
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
      "domain": "skillshare.com",
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
      "origin": "https://sub.skillshare.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://skillshare.com/"
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
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 26,
    "notable": [
      "auth.skillshare.com",
      "cloudflare.ingress.ops.skillshare.com",
      "dev.skillshare.com",
      "eng.ops.skillshare.com",
      "events.docs.internal.skillshare.com",
      "help.skillshare.com",
      "ops.skillshare.com",
      "prod.atlas.blog.skillshare.com",
      "stg.atlas.blog.skillshare.com"
    ],
    "sample": [
      "auth-development.skillshare.com",
      "auth-staging.skillshare.com",
      "auth-test.skillshare.com",
      "auth.skillshare.com",
      "blueshift-sandbox.skillshare.com",
      "brand.skillshare.com",
      "click.skillshare.com",
      "cloudflare.ingress.ops.skillshare.com",
      "design.skillshare.com",
      "dev.skillshare.com",
      "dreamjob.skillshare.com",
      "eng.ops.skillshare.com",
      "events.docs.internal.skillshare.com",
      "help.skillshare.com",
      "legal.skillshare.com",
      "ops.skillshare.com",
      "partners.skillshare.com",
      "phoenix-demo.skillshare.com",
      "preferences.skillshare.com",
      "prod.atlas.blog.skillshare.com"
    ],
    "dangling": [
      "dev.skillshare.com"
    ]
  },
  "apex_txt": [
    "h1-domain-verification=J1qQPbBWpbBxGVL3i3h1dpw2rX1NwHEZhnWeRNNP5L9qB2DX",
    "google-site-verification=DshzQEv8w03dqk3NErt1hlkBaXsKdTMaUfBY1J-8Wic",
    "facebook-domain-verification=va9wk46fanagqpr4rc6sp4d3gap007",
    "anthropic-domain-verification-0j2hh2=VDsV2bFDu3c0IZWFsXlG1WQ4h",
    "jamf-site-verification=jsRO5e76-EWTHTbtESgo9g"
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
      "not_before": "20260819160716",
      "not_after": "20261117170713"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/site/search/",
      "/dashboard/",
      "/reset-password/",
      "/mixpanel/",
      "/search?",
      "/sessions/",
      "/checkout",
      "/reviews",
      "/cdn-cgi/",
      "/.well-known/",
      "/apple-app-site-association"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 9.7,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
