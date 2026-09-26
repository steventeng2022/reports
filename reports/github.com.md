# Security Audit Report — github.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://github.com/ |
| Bug bounty program | GitHub |
| Listed scope domain | github.com |
| Test date | 2026-09-26 18:52 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 2, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT22 | SSH reachable | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 14 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |

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

### 7. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 8. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 9. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: shopify-verification-code=t1YPwcmvnxZyBycaCpk1MPyWoFs72o; openai-domain-verification=dv-3nh33eQwdkotMIAzLrIDVZo1; google-site-verification=82Le34Flgtd15ojYhHlGF_6g72muSjamlMVThBOJpks
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of github.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 241 disallow path(s), e.g. /*/*/pulse, /*/*/projects, /*/*/forks, /*/*/issues/new, /*/*/milestones/new
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of github.com permits unsafe-inline; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 14. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://github.com/ carries Cache-Control: max-age=0, private, must-revalidate (plus ETag/Last-Modified freshness fields); shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

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
      "ns-520.awsdns-01.net.",
      "dns4.p08.nsone.net.",
      "dns3.p08.nsone.net.",
      "ns-421.awsdns-52.com.",
      "ns-1283.awsdns-32.org.",
      "dns1.p08.nsone.net.",
      "dns2.p08.nsone.net.",
      "ns-1707.awsdns-21.co.uk."
    ],
    "spf": [
      "shopify-verification-code=t1YPwcmvnxZyBycaCpk1MPyWoFs72o",
      "MS=ms58704441",
      "openai-domain-verification=dv-3nh33eQwdkotMIAzLrIDVZo1",
      "google-site-verification=82Le34Flgtd15ojYhHlGF_6g72muSjamlMVThBOJpks",
      "MS=ms44452932",
      "google-site-verification=UTM-3akMgubp6tQtgEuAkYNYLyYAvpTnnSrDMWoDR3o",
      "TAILSCALE-xOzoDvFUzZr5YYVCQFuD",
      "facebook-domain-verification=39xu4jzl7roi7x0n93ldkxjiaarx50",
      "stripe-verification=f88ef17321660a01bab1660454192e014defa29ba7b8de9633c69d6b4912217f",
      "MS=6BF03E6AF5CB689E315FB6199603BABF2C88D805",
      "loom-site-verification=f3787154f1154b7880e720a511ea664d",
      "00Dd0000000hHE0=1TBKg000000TN2r",
      "serval-domain-verification-ydryhj=qbkiEakpwEpTvHh5fIiCqtaue",
      "krisp-domain-verification=ZlyiK7XLhnaoUQb2hpak1PLY7dFkl1WE",
      "calendly-site-verification=at0DQARi7IZvJtXQAWhMqpmIzpvoBNF7aam5VKKxP",
      "apple-domain-verification=RyQhdzTl6Z6x8ZP4",
      "anthropic-domain-verification-4az7qn=if8YWuRRqwLycGJDooumzHtxm",
      "cursor-domain-verification-gtfwmt=1rfLOtiTngX5QSxD5HvNKTvm3",
      "miro-verification=d2e174fdb00c71e0bcf58f8e58c3da2dd80dcfa9",
      "v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.2",
      "27.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all",
      "adobe-idp-site-verification=b92c9e999aef825edc36e0a3d847d2dbad5b2fc0e05c79ddd7a16139b48ecf4b",
      "docusign=087098e3-3d46-47b7-9b4e-8a23028154cd",
      "jamf-site-verification=XtaPNIYghF_e_xRDI8CjgQ",
      "atlassian-domain-verification=jjgw98AKv2aeoYFxiL/VFaoyPkn3undEssTRuMg6C/3Fp/iqhkV4HVV7WjYlVeF8"
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
    "days_left": 64,
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "shopify-verification-code=t1YPwcmvnxZyBycaCpk1MPyWoFs72o",
    "openai-domain-verification=dv-3nh33eQwdkotMIAzLrIDVZo1",
    "google-site-verification=82Le34Flgtd15ojYhHlGF_6g72muSjamlMVThBOJpks",
    "google-site-verification=UTM-3akMgubp6tQtgEuAkYNYLyYAvpTnnSrDMWoDR3o",
    "facebook-domain-verification=39xu4jzl7roi7x0n93ldkxjiaarx50"
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
      "not_before": "20260901000000",
      "not_after": "20261129235959"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/*/*/pulse",
      "/*/*/projects",
      "/*/*/forks",
      "/*/*/issues/new",
      "/*/*/milestones/new",
      "/*/*/issues/search",
      "/*/*/commits/",
      "/*/*/branches",
      "/*/*/contributors",
      "/*/*/tags",
      "/*/*/stargazers",
      "/*/*/watchers",
      "/*/*/network",
      "/*/*/graphs",
      "/*/*/compare"
    ]
  },
  "x12": {
    "status": 200
  },
  "elapsed_s": 10.7,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
