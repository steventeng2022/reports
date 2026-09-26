# Security Audit Report — meetup.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://meetup.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | meetup.com |
| Test date | 2026-09-25 23:13 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | CT1 | 55 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=7776000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

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

### 7. [INFO] 55 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.meetup.com, api.int.dev.meetup.com, api.int.meetup.com, api.meetup.com, auth.blt.meetup.com, dev.m2mpay.meetup.com, dev.memberpay.meetup.com, help.meetup.com, redash.cloud.dev.meetup.com, test.dev.meetup.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "meetup.com",
  "dns": {
    "a": [
      "151.101.194.217",
      "151.101.2.217",
      "151.101.66.217",
      "151.101.130.217"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 1)"
    ],
    "ns": [
      "ns-1378.awsdns-44.org.",
      "ns-40.awsdns-05.com.",
      "ns-919.awsdns-50.net.",
      "ns-1782.awsdns-30.co.uk."
    ],
    "spf": [
      "_gvhn8tc5d0bjvpfjwr6izofm3rw1rzm",
      "v=spf1 include:mail.zendesk.com include:_spf.google.com include:_spf.sparkpostmail.com ~all",
      "google-site-verification=LzTshnYHTmh-qKj8qWTYVNo408Av35GqfZQxSopIWEo",
      "docusign=0a856615-3cca-4967-af2e-aa849ca42de2",
      "google-site-verification=892t2MaS4SZsb48SSg1A3ABMz3RTC_BD0aedsHeQcPs",
      "_gh-bending-spoons-e=da6293536f",
      "_globalsign-domain-verification=hnJMGmZ5nxkDzoVy5--BmuTT2DIF9hm5OQ87d_jorS",
      "facebook-domain-verification=rgyjx6tabxhbz0vs8jznk3h7kw9igq",
      "google-site-verification=UHCBNwoUShRSmjmm8U3HWmmtbqIV7dsuHyMrhUDOCtQ",
      "google-site-verification=JU1AoGj_pC_wB0Jxu62NnaIktGqrX8wTvBo9i8XRwHw",
      "rippling-domain-verification=217697edd61756fc",
      "google-site-verification=d7aAADk1yxzIsb2QOmZY6COjV2y0iPhwwSmmNpJgEfM",
      "google-site-verification=sc2QcwRmidYh2YB2ghH7c9-GgAZQu0QMtcFrUURtSJQ",
      "google-site-verification=-YC-JRzsddf4MU6k9PhCUBV78tg9R3zqO8WWK7i1SHA"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.bendingspoons.com; sp=reject;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=meetup.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2025 Q4",
    "notBefore": "Dec  9 17:39:12 2025 GMT",
    "notAfter": "Jan 10 17:39:11 2027 GMT",
    "san": [
      "meetup.com"
    ],
    "days_left": 106,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "151.101.194.217",
    "open": []
  },
  "https": {
    "status": 308,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.meetup.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://meetup.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 308",
    "/redirect?next=https://evil-auditor.example/x -> 308",
    "/go?url=https://evil-auditor.example/x -> 308",
    "/url?url=https://evil-auditor.example/x -> 308"
  ],
  "paths": {
    "/robots.txt": 308,
    "/sitemap.xml": 308,
    "/.well-known/security.txt": 308,
    "/security.txt": 308,
    "/.git/HEAD": 308,
    "/.git/config": 308,
    "/.env": 403,
    "/.htaccess": 308,
    "/wp-login.php": 308,
    "/phpmyadmin/index.php": 308,
    "/server-status": 308,
    "/api/": 308
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 55,
    "notable": [
      "admin.meetup.com",
      "api.int.dev.meetup.com",
      "api.int.meetup.com",
      "api.meetup.com",
      "auth.blt.meetup.com",
      "dev.m2mpay.meetup.com",
      "dev.memberpay.meetup.com",
      "help.meetup.com",
      "redash.cloud.dev.meetup.com",
      "test.dev.meetup.com"
    ],
    "sample": [
      "admin.meetup.com",
      "airflow.blt.meetup.com",
      "analytics-tracking.meetup.com",
      "api.int.dev.meetup.com",
      "api.int.meetup.com",
      "api.meetup.com",
      "auth.blt.meetup.com",
      "bamboo.blt.meetup.com",
      "bazel-cache.blt.meetup.com",
      "blt.meetup.com",
      "campaign-generator.meetup.com",
      "clicks.meetup.com",
      "console.meetup.com",
      "dbhsejcg.meetup.com",
      "dev.m2mpay.meetup.com",
      "dev.memberpay.meetup.com",
      "dp-event-search-edge.meetup.com",
      "dummy.blt.meetup.com",
      "email-analytics.meetup.com",
      "experiences.meetup.com"
    ]
  },
  "elapsed_s": 35.6,
  "rechecked": "2026-09-25 23:12 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
