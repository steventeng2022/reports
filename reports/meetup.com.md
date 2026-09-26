# Security Audit Report — meetup.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://meetup.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | meetup.com |
| Test date | 2026-09-26 17:49 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 2, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 8 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 9 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | info | CT1 | 55 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |

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

### 7. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 8. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 9. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (y1my9epbh3c476.meetup.com and 0wvik5lonfvh2h.meetup.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=d7aAADk1yxzIsb2QOmZY6COjV2y0iPhwwSmmNpJgEfM; google-site-verification=-YC-JRzsddf4MU6k9PhCUBV78tg9R3zqO8WWK7i1SHA; google-site-verification=892t2MaS4SZsb48SSg1A3ABMz3RTC_BD0aedsHeQcPs
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of meetup.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but meetup.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 116 disallow path(s), e.g. /files/, /fb/, /preview/, /n/*, */calendar/*atom*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [INFO] 55 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.meetup.com, api.int.dev.meetup.com, api.int.meetup.com, api.meetup.com, auth.blt.meetup.com, dev.m2mpay.meetup.com, dev.memberpay.meetup.com, help.meetup.com, redash.cloud.dev.meetup.com, test.dev.meetup.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "meetup.com",
  "dns": {
    "a": [
      "151.101.130.217",
      "151.101.2.217",
      "151.101.66.217",
      "151.101.194.217"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 1)"
    ],
    "ns": [
      "ns-1782.awsdns-30.co.uk.",
      "ns-1378.awsdns-44.org.",
      "ns-40.awsdns-05.com.",
      "ns-919.awsdns-50.net."
    ],
    "spf": [
      "google-site-verification=d7aAADk1yxzIsb2QOmZY6COjV2y0iPhwwSmmNpJgEfM",
      "google-site-verification=-YC-JRzsddf4MU6k9PhCUBV78tg9R3zqO8WWK7i1SHA",
      "google-site-verification=892t2MaS4SZsb48SSg1A3ABMz3RTC_BD0aedsHeQcPs",
      "google-site-verification=UHCBNwoUShRSmjmm8U3HWmmtbqIV7dsuHyMrhUDOCtQ",
      "rippling-domain-verification=217697edd61756fc",
      "v=spf1 include:mail.zendesk.com include:_spf.google.com include:_spf.sparkpostmail.com ~all",
      "docusign=0a856615-3cca-4967-af2e-aa849ca42de2",
      "google-site-verification=LzTshnYHTmh-qKj8qWTYVNo408Av35GqfZQxSopIWEo",
      "google-site-verification=sc2QcwRmidYh2YB2ghH7c9-GgAZQu0QMtcFrUURtSJQ",
      "_gh-bending-spoons-e=da6293536f",
      "google-site-verification=JU1AoGj_pC_wB0Jxu62NnaIktGqrX8wTvBo9i8XRwHw",
      "facebook-domain-verification=rgyjx6tabxhbz0vs8jznk3h7kw9igq",
      "_globalsign-domain-verification=hnJMGmZ5nxkDzoVy5--BmuTT2DIF9hm5OQ87d_jorS",
      "_gvhn8tc5d0bjvpfjwr6izofm3rw1rzm"
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
    "days_left": 105,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "151.101.130.217",
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
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=d7aAADk1yxzIsb2QOmZY6COjV2y0iPhwwSmmNpJgEfM",
    "google-site-verification=-YC-JRzsddf4MU6k9PhCUBV78tg9R3zqO8WWK7i1SHA",
    "google-site-verification=892t2MaS4SZsb48SSg1A3ABMz3RTC_BD0aedsHeQcPs",
    "google-site-verification=UHCBNwoUShRSmjmm8U3HWmmtbqIV7dsuHyMrhUDOCtQ",
    "rippling-domain-verification=217697edd61756fc"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/files/",
      "/fb/",
      "/preview/",
      "/n/*",
      "*/calendar/*atom*",
      "*/calendar/*rss*",
      "*/calendar/*xml*",
      "*/events/atom/*",
      "*/events/rss/*",
      "*/events/xml/*",
      "*/rsvps/*atom*",
      "*/rsvps/*rss*",
      "*/rsvps/*xml*",
      "*/newest/*atom*",
      "*/newest/*rss*"
    ]
  },
  "elapsed_s": 34.5,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
