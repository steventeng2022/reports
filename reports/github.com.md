# Security Audit Report — github.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://github.com/ |
| Bug bounty program | GitHub |
| Listed scope domain | github.com |
| Test date | 2026-09-25 09:47 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 0, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT22 | SSH reachable | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] SSH reachable (`PRT22`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 20.27.177.113:22 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: github.com
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: github.com
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

## Evidence (raw response observations)

```json
{
  "domain": "github.com",
  "dns": {
    "a": [
      "20.27.177.113"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "github-com.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "dns3.p08.nsone.net.",
      "ns-421.awsdns-52.com.",
      "ns-520.awsdns-01.net.",
      "dns4.p08.nsone.net.",
      "dns1.p08.nsone.net.",
      "ns-1283.awsdns-32.org.",
      "ns-1707.awsdns-21.co.uk.",
      "dns2.p08.nsone.net."
    ],
    "spf": [
      "atlassian-domain-verification=jjgw98AKv2aeoYFxiL/VFaoyPkn3undEssTRuMg6C/3Fp/iqhkV4HVV7WjYlVeF8",
      "MS=ms58704441",
      "v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.2",
      "27.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all",
      "apple-domain-verification=RyQhdzTl6Z6x8ZP4",
      "krisp-domain-verification=ZlyiK7XLhnaoUQb2hpak1PLY7dFkl1WE",
      "shopify-verification-code=t1YPwcmvnxZyBycaCpk1MPyWoFs72o",
      "calendly-site-verification=at0DQARi7IZvJtXQAWhMqpmIzpvoBNF7aam5VKKxP",
      "openai-domain-verification=dv-3nh33eQwdkotMIAzLrIDVZo1",
      "serval-domain-verification-ydryhj=qbkiEakpwEpTvHh5fIiCqtaue",
      "TAILSCALE-xOzoDvFUzZr5YYVCQFuD",
      "MS=6BF03E6AF5CB689E315FB6199603BABF2C88D805",
      "miro-verification=d2e174fdb00c71e0bcf58f8e58c3da2dd80dcfa9",
      "00Dd0000000hHE0=1TBKg000000TN2r",
      "stripe-verification=f88ef17321660a01bab1660454192e014defa29ba7b8de9633c69d6b4912217f",
      "google-site-verification=UTM-3akMgubp6tQtgEuAkYNYLyYAvpTnnSrDMWoDR3o",
      "cursor-domain-verification-gtfwmt=1rfLOtiTngX5QSxD5HvNKTvm3",
      "facebook-domain-verification=39xu4jzl7roi7x0n93ldkxjiaarx50",
      "docusign=087098e3-3d46-47b7-9b4e-8a23028154cd",
      "jamf-site-verification=XtaPNIYghF_e_xRDI8CjgQ",
      "adobe-idp-site-verification=b92c9e999aef825edc36e0a3d847d2dbad5b2fc0e05c79ddd7a16139b48ecf4b",
      "MS=ms44452932",
      "anthropic-domain-verification-4az7qn=if8YWuRRqwLycGJDooumzHtxm",
      "google-site-verification=82Le34Flgtd15ojYhHlGF_6g72muSjamlMVThBOJpks",
      "loom-site-verification=f3787154f1154b7880e720a511ea664d"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@github.com; ruf=mailto:dmarc@github.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=github.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA DV E36",
    "notBefore": "Sep  1 00:00:00 2026 GMT",
    "notAfter": "Nov 29 23:59:59 2026 GMT",
    "san": [
      "github.com",
      "www.github.com"
    ],
    "days_left": 65,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "20.27.177.113",
    "open": [
      22
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "GitHub · Change is constant. GitHub keeps you ahead. · GitHub"
  },
  "mixed_content": [],
  "tech": [
    "Server: github.com"
  ],
  "cookies": [
    {
      "samesite": "lax"
    },
    {
      "domain": ".github.com",
      "samesite": "lax"
    },
    {
      "domain": ".github.com",
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.github.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://github.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 406,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 406,
    "/phpmyadmin/index.php": 404,
    "/server-status": 200,
    "/api/": 404
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 31.8,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
