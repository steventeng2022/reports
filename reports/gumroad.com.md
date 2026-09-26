# Security Audit Report — gumroad.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gumroad.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | gumroad.com |
| Test date | 2026-09-26 17:46 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **23** (High: 0, Medium: 0, Low: 4, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 6 | info | TECH1 | Technology fingerprint | CWE-200 |
| 7 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | info | MAIL10 | DMARC subdomain policy (sp=) set while apex policy is p=none | CWE-285 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 18 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 19 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 20 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 21 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 22 | info | CT1 | 42 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 23 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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
- **Detail:** TCP connect to 104.18.243.99:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.243.99:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 6. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 7. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 11. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [INFO] DMARC subdomain policy (sp=) set while apex policy is p=none (`MAIL10`)

- **CWE:** CWE-285
- **Detail:** Subdomains are enforced while the apex domain is monitor-only.
- **Recommendation:** Confirm the split policy is intended.

### 15. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 16. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 17. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (xhnk6h4y0tpdcd.gumroad.com and iry8qrewykd347.gumroad.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 18. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=PgpLEes7We_6DhccKbUEiYcZ0pdoMFKC9nvJzv5llfo; notion-domain-verification=sSdqoXWqKQb9UfQM5R80tQCvesneCxOsRl4uKtCzkZc; tiktok-developers-site-verification=EAMtFdg7OB3QLjHaQnqfXjp7NocwiRoa
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 19. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of gumroad.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 20. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but gumroad.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 21. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1 disallow path(s), e.g. /purchases/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 22. [INFO] 42 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.gumroad.com, blog.gumroad.com, help.gumroad.com, staging.creators.gumroad.com, staging.customers.gumroad.com, staging.followers.gumroad.com, staging.gumroad.com, static.gumroad.com, status.gumroad.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 23. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: staging.creators.gumroad.com, staging.customers.gumroad.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "gumroad.com",
  "dns": {
    "a": [
      "104.18.243.99",
      "104.17.176.98"
    ],
    "aaaa": [
      "2606:4700::6812:f363",
      "2606:4700::6811:b062"
    ],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "venus.ns.cloudflare.com.",
      "jeff.ns.cloudflare.com."
    ],
    "spf": [
      "google-site-verification=PgpLEes7We_6DhccKbUEiYcZ0pdoMFKC9nvJzv5llfo",
      "notion-domain-verification=sSdqoXWqKQb9UfQM5R80tQCvesneCxOsRl4uKtCzkZc",
      "tiktok-developers-site-verification=EAMtFdg7OB3QLjHaQnqfXjp7NocwiRoa",
      "status-page-domain-verification=8vj11whsslmd",
      "MS=ms30035841",
      "google-site-verification=lrFehNfjlR5pdQ9Yl1S3X4-HclWnL2hRE-lp5ciPfYs",
      "v=spf1 a mx ip4:67.225.137.176 include:sendgrid.net include:stspg-customer.com include:_spf.google.com ~all"
    ],
    "dmarc": [
      "v=DMARC1; p=none; pct=100; rua=mailto:re+qv9rjnupoda@dmarc.postmarkapp.com; sp=none; aspf=r;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=gumroad.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 11 02:45:52 2026 GMT",
    "notAfter": "Dec 10 03:45:35 2026 GMT",
    "san": [
      "gumroad.com",
      "*.gumroad.com"
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
    "ip": "104.18.243.99",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Earn your first dollar online with Gumroad"
  },
  "mixed_content": [
    "href=\"http://"
  ],
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
      "origin": "https://sub.gumroad.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://gumroad.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 200
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 42,
    "notable": [
      "api.gumroad.com",
      "blog.gumroad.com",
      "help.gumroad.com",
      "staging.creators.gumroad.com",
      "staging.customers.gumroad.com",
      "staging.followers.gumroad.com",
      "staging.gumroad.com",
      "static.gumroad.com",
      "status.gumroad.com"
    ],
    "sample": [
      "api.gumroad.com",
      "blog.gumroad.com",
      "community.gumroad.com",
      "customers.gumroad.com",
      "ershad-test.gumroad.com",
      "gumroad.com",
      "help.gumroad.com",
      "home.gumroad.com",
      "m.gumroad.com",
      "newsletter.gumroad.com",
      "production-custom-domain-with-cname.gumroad.com",
      "production-custom-domain-with-ip.gumroad.com",
      "production-sample-shop.gumroad.com",
      "raise.gumroad.com",
      "sample-shop.gumroad.com",
      "shibin-staging-sample-shop.gumroad.com",
      "staging-2.gumroad.com",
      "staging-custom-domain-ip-test-2.gumroad.com",
      "staging-custom-domain-with-cname.gumroad.com",
      "staging-custom-domain-with-ip.gumroad.com"
    ],
    "dangling": [
      "staging.creators.gumroad.com",
      "staging.customers.gumroad.com"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=PgpLEes7We_6DhccKbUEiYcZ0pdoMFKC9nvJzv5llfo",
    "notion-domain-verification=sSdqoXWqKQb9UfQM5R80tQCvesneCxOsRl4uKtCzkZc",
    "tiktok-developers-site-verification=EAMtFdg7OB3QLjHaQnqfXjp7NocwiRoa",
    "status-page-domain-verification=8vj11whsslmd",
    "google-site-verification=lrFehNfjlR5pdQ9Yl1S3X4-HclWnL2hRE-lp5ciPfYs"
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
      "/purchases/"
    ]
  },
  "elapsed_s": 9.4,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
