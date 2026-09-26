# Security Audit Report — flipboard.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://flipboard.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | flipboard.com |
| Test date | 2026-09-26 18:51 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 3, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | low | MAIL9 | DMARC enforces (p=quarantine) but has no reporting address (rua) | CWE-285 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 14 | info | CT1 | 12 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 7. [LOW] DMARC enforces (p=quarantine) but has no reporting address (rua) (`MAIL9`)

- **CWE:** CWE-285
- **Detail:** Without a rua= reporting address the policy cannot be tuned; mis-sends may be silently quarantined.
- **Recommendation:** Add a rua= reporting mailbox to the DMARC record.

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
- **Detail:** Apex TXT records with verification/token content: anthropic-domain-verification-1avd9b=GWlaVK7cM1UrnAecUR0PhzRI7; google-site-verification=196ICmalqDggbij227IKpDuO8wjKIGJOoWQUKVR0B0U; have-i-been-pwned-verification=6b731851fd4ef8a6d49f6f8ff8f3eed4
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of flipboard.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 19 disallow path(s), e.g. /, /analytics/, /api/, /bookmarklet/, /editor/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 54.192.248.101 carries PTR server-54-192-248-101.tpe53.r.cloudfront.net. for flipboard.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 14. [INFO] 12 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "flipboard.com",
  "dns": {
    "a": [
      "54.192.248.101",
      "54.192.248.48",
      "54.192.248.59",
      "54.192.248.119"
    ],
    "aaaa": [
      "2600:9000:202f:2600:15:d33e:2640:93a1",
      "2600:9000:202f:1800:15:d33e:2640:93a1",
      "2600:9000:202f:1400:15:d33e:2640:93a1",
      "2600:9000:202f:c400:15:d33e:2640:93a1",
      "2600:9000:202f:e00:15:d33e:2640:93a1",
      "2600:9000:202f:2800:15:d33e:2640:93a1",
      "2600:9000:202f:8400:15:d33e:2640:93a1",
      "2600:9000:202f:1c00:15:d33e:2640:93a1"
    ],
    "cname": null,
    "mx": [
      "aspmx5.googlemail.com (pref 30)",
      "aspmx4.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-60.awsdns-07.com.",
      "ns-816.awsdns-38.net.",
      "ns-1756.awsdns-27.co.uk.",
      "ns-1510.awsdns-60.org."
    ],
    "spf": [
      "anthropic-domain-verification-1avd9b=GWlaVK7cM1UrnAecUR0PhzRI7",
      "google-site-verification=196ICmalqDggbij227IKpDuO8wjKIGJOoWQUKVR0B0U",
      "have-i-been-pwned-verification=6b731851fd4ef8a6d49f6f8ff8f3eed4",
      "google-site-verification=9rExE5dYg3CPZ3GFGvrkj2MbbKAkdHHH5aRUYSnq9w4",
      "google-site-verification=BqjKftnKldO1vP49cSkz2ryHMLPk5y3V6-JlkIhUo1U",
      "_wpengine-sso-challenge.flipboard.com= 2KkDEiUGF0IvgPeA6uHIcV57z9H",
      "_wpengine-sso-challenge= 2KkDEiUGF0IvgPeA6uHIcV57z9H",
      "atlassian-domain-verification=dZ8g4eOwcpvhvx5AD10LH0gUSjKTUUgORwal07qANXl3412gq8IYKOlI4oa4llnl",
      "google-site-verification=eqogjmVDZB-9UMYUFvv5OlEO_a20KZadbY7DJw35Dys",
      "v=spf1 include:servers.mcsv.net include:sendgrid.net include:_spf.google.com -all",
      "google-site-verification=EU2djlhiCyLFRE6dqL0HEIwLSclUSRLzkbvQ4ObXr7I",
      "google-site-verification=47g-PnfQPJHjb8Ze5YYF-hF2ABg67yFQc-kwrSv8PAY"
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
    "days_left": 166,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.101",
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
  "apex_txt": [
    "anthropic-domain-verification-1avd9b=GWlaVK7cM1UrnAecUR0PhzRI7",
    "google-site-verification=196ICmalqDggbij227IKpDuO8wjKIGJOoWQUKVR0B0U",
    "have-i-been-pwned-verification=6b731851fd4ef8a6d49f6f8ff8f3eed4",
    "google-site-verification=9rExE5dYg3CPZ3GFGvrkj2MbbKAkdHHH5aRUYSnq9w4",
    "google-site-verification=BqjKftnKldO1vP49cSkz2ryHMLPk5y3V6-JlkIhUo1U"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20260211000000",
      "not_after": "20270311235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/analytics/",
      "/api/",
      "/bookmarklet/",
      "/editor/",
      "/getflipit",
      "/logout",
      "/notifications",
      "/post",
      "/oauth/",
      "/redirect?",
      "/search/",
      "/signout",
      "/static/ebsa/",
      "/static/gfs/"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-54-192-248-101.tpe53.r.cloudfront.net."
    ]
  },
  "elapsed_s": 14.2,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
