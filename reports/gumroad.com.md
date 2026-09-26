# Security Audit Report — gumroad.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gumroad.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | gumroad.com |
| Test date | 2026-09-25 23:12 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 3, Info: 12)

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
| 14 | info | CT1 | 42 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 15 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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
- **Detail:** TCP connect to 104.17.176.98:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.17.176.98:8443 succeeded (state-only check, no payload sent).
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

### 14. [INFO] 42 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.gumroad.com, blog.gumroad.com, help.gumroad.com, staging.creators.gumroad.com, staging.customers.gumroad.com, staging.followers.gumroad.com, staging.gumroad.com, static.gumroad.com, status.gumroad.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 15. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: staging.creators.gumroad.com, staging.customers.gumroad.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "gumroad.com",
  "dns": {
    "a": [
      "104.17.176.98",
      "104.18.243.99"
    ],
    "aaaa": [
      "2606:4700::6811:b062",
      "2606:4700::6812:f363"
    ],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "aspmx2.googlemail.com (pref 10)"
    ],
    "ns": [
      "venus.ns.cloudflare.com.",
      "jeff.ns.cloudflare.com."
    ],
    "spf": [
      "MS=ms30035841",
      "google-site-verification=PgpLEes7We_6DhccKbUEiYcZ0pdoMFKC9nvJzv5llfo",
      "google-site-verification=lrFehNfjlR5pdQ9Yl1S3X4-HclWnL2hRE-lp5ciPfYs",
      "status-page-domain-verification=8vj11whsslmd",
      "v=spf1 a mx ip4:67.225.137.176 include:sendgrid.net include:stspg-customer.com include:_spf.google.com ~all",
      "tiktok-developers-site-verification=EAMtFdg7OB3QLjHaQnqfXjp7NocwiRoa",
      "notion-domain-verification=sSdqoXWqKQb9UfQM5R80tQCvesneCxOsRl4uKtCzkZc"
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
    "days_left": 75,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.17.176.98",
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
  "elapsed_s": 21.6,
  "rechecked": "2026-09-25 23:12 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
