# Security Audit Report — skillshare.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://skillshare.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | skillshare.com |
| Test date | 2026-09-26 14:55 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 2, Info: 9)

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
      "aspmx3.googlemail.com (pref 50)",
      "aspmx.l.google.com (pref 10)",
      "aspmx4.googlemail.com (pref 50)",
      "alt1.aspmx.l.google.com (pref 20)",
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx5.googlemail.com (pref 50)"
    ],
    "ns": [
      "ashe.skillshare.com.",
      "garen.skillshare.com."
    ],
    "spf": [
      "jamf-site-verification=jsRO5e76-EWTHTbtESgo9g",
      "qyylpgj14chmtmds8wgz7j8lqwrd44tt",
      "v=spf1 include:_spf0.skillshare.com include:_spf1.skillshare.com include:_spf2.skillshare.com include:_spf3.skillshare.com include:sendgrid.net include:_spf.google.com include:sendgrid.net include:_spf.google.com ip4:23.21.109.197 ip4:23.21.109.212 ~all",
      "anthropic-domain-verification-0j2hh2=VDsV2bFDu3c0IZWFsXlG1WQ4h",
      "miro-verification=2accb01b1b638f37ee0cd64452e2faaa57e1cdf6",
      "firebase=skillshare-creator-dev",
      "google-site-verification=DshzQEv8w03dqk3NErt1hlkBaXsKdTMaUfBY1J-8Wic",
      "apple-domain-verification=Hb38JzhNUvqf3hR2",
      "h1-domain-verification=J1qQPbBWpbBxGVL3i3h1dpw2rX1NwHEZhnWeRNNP5L9qB2DX",
      "facebook-domain-verification=va9wk46fanagqpr4rc6sp4d3gap007",
      "9p1q7gjsjf6jgqmkdvbdxhxch33lxzsv",
      "google-site-verification=mcHpWbpzXVe4BOFgp5ijuXXqIf7OMoH1Z7ctm2mlBDc",
      "mixpanel-domain-verify=739bd2fb-b682-4acf-9689-e94b74a61621",
      "amazonses:FA3mpwGhZzBmEIrp3iQXIXa3+umrH8ce03vBPry8tuI=",
      "fw8mkvj2p2lgsk7crsrgylmvpzf0fkkw",
      "atlassian-domain-verification=caa1SXVOa/jn5JVpUdP/OCpP1t9l1rz9ikhEsdPLJYGgYWquY6v2tDOvBhNoJG99",
      "openai-domain-verification=dv-98OuGQNGSB3R75FCYqMmzHqw"
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
    "days_left": 52,
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 8.2,
  "rechecked": "2026-09-26 14:53 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
