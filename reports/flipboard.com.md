# Security Audit Report — flipboard.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://flipboard.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | flipboard.com |
| Test date | 2026-09-25 07:46 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 2, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | CT1 | 12 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 5. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 6. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 7. [INFO] 12 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "flipboard.com",
  "dns": {
    "a": [
      "54.192.248.119",
      "54.192.248.59",
      "54.192.248.101",
      "54.192.248.48"
    ],
    "aaaa": [
      "2600:9000:202f:4000:15:d33e:2640:93a1",
      "2600:9000:202f:5c00:15:d33e:2640:93a1",
      "2600:9000:202f:8c00:15:d33e:2640:93a1",
      "2600:9000:202f:9c00:15:d33e:2640:93a1",
      "2600:9000:202f:7800:15:d33e:2640:93a1",
      "2600:9000:202f:3600:15:d33e:2640:93a1",
      "2600:9000:202f:6c00:15:d33e:2640:93a1",
      "2600:9000:202f:bc00:15:d33e:2640:93a1"
    ],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx5.googlemail.com (pref 30)",
      "aspmx4.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-60.awsdns-07.com.",
      "ns-1756.awsdns-27.co.uk.",
      "ns-816.awsdns-38.net.",
      "ns-1510.awsdns-60.org."
    ],
    "spf": [
      "google-site-verification=eqogjmVDZB-9UMYUFvv5OlEO_a20KZadbY7DJw35Dys",
      "google-site-verification=9rExE5dYg3CPZ3GFGvrkj2MbbKAkdHHH5aRUYSnq9w4",
      "google-site-verification=EU2djlhiCyLFRE6dqL0HEIwLSclUSRLzkbvQ4ObXr7I",
      "google-site-verification=47g-PnfQPJHjb8Ze5YYF-hF2ABg67yFQc-kwrSv8PAY",
      "v=spf1 include:servers.mcsv.net include:sendgrid.net include:_spf.google.com ip4:54.243.226.239 ip4:107.22.115.145 -all",
      "anthropic-domain-verification-1avd9b=GWlaVK7cM1UrnAecUR0PhzRI7",
      "have-i-been-pwned-verification=6b731851fd4ef8a6d49f6f8ff8f3eed4",
      "google-site-verification=196ICmalqDggbij227IKpDuO8wjKIGJOoWQUKVR0B0U",
      "_wpengine-sso-challenge.flipboard.com= 2KkDEiUGF0IvgPeA6uHIcV57z9H",
      "google-site-verification=BqjKftnKldO1vP49cSkz2ryHMLPk5y3V6-JlkIhUo1U",
      "_wpengine-sso-challenge= 2KkDEiUGF0IvgPeA6uHIcV57z9H",
      "atlassian-domain-verification=dZ8g4eOwcpvhvx5AD10LH0gUSjKTUUgORwal07qANXl3412gq8IYKOlI4oa4llnl"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.flipboard.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Feb 11 00:00:00 2026 GMT",
    "notAfter": "Mar 11 23:59:59 2027 GMT",
    "san": [
      "*.flipboard.com",
      "www.flipboard.com",
      "flipboard.com"
    ],
    "days_left": 167,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.119",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Flipboard: Your Social Magazine"
  },
  "mixed_content": [],
  "cookies": [
    {
      "domain": "flipboard.com"
    },
    {},
    {}
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.flipboard.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://flipboard.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 403,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 12,
    "notable": [],
    "sample": [
      "about.flipboard.com",
      "analytics.flipboard.com",
      "applink.flipboard.com",
      "engineering.flipboard.com",
      "flipboard.com",
      "fliptest.flipboard.com",
      "pea.flipboard.com",
      "production-v3.eks.flipboard.com",
      "production-v4.eks.flipboard.com",
      "sli.flipboard.com",
      "wp.flipboard.com",
      "www.flipboard.com"
    ]
  },
  "elapsed_s": 11.6,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
