# Security Audit Report — facebook.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://facebook.com/ |
| Bug bounty program | Facebook |
| Listed scope domain | facebook.com |
| Test date | 2026-09-26 18:51 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 7, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 13 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | CT1 | 56 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 8 days (notAfter Oct  4 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=15552000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 13. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.facebook.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: zoom-domain-verification=4b2ef4e1-6dee-4483-9869-9bef353fd147; google-site-verification=A2WZWCNQHrGV_TWwKh6KHY90tY0SHZo_RnyMJoDaG0s; facebook-domain-verification=y7isfmi3kzyg1r4wophh9vyb6pgbda
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of facebook.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1160 disallow path(s), e.g. /, /, /, /, /
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 57.144.92.1 carries PTR edge-star-mini-shv-01-tpe5.facebook.com. for facebook.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] 56 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: beta.facebook.com, dev.facebook.com, fb.beta.facebook.com, hr.facebook.com, interngraph.staging.scgraph.facebook.com, m.beta.facebook.com, secure.beta.facebook.com, smtpin.mx.facebook.com, staging.scgraph.facebook.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "facebook.com",
  "dns": {
    "a": [
      "57.144.92.1"
    ],
    "aaaa": [
      "2a03:2880:f325:1:face:b00c:0:25de"
    ],
    "cname": null,
    "mx": [
      "smtpin.vvv.facebook.com (pref 10)"
    ],
    "ns": [
      "a.ns.facebook.com.",
      "b.ns.facebook.com.",
      "d.ns.facebook.com.",
      "c.ns.facebook.com."
    ],
    "spf": [
      "zoom-domain-verification=4b2ef4e1-6dee-4483-9869-9bef353fd147",
      "google-site-verification=A2WZWCNQHrGV_TWwKh6KHY90tY0SHZo_RnyMJoDaG0s",
      "facebook-domain-verification=y7isfmi3kzyg1r4wophh9vyb6pgbda",
      "zoom-domain-verification=ZOOM_verify_e6c41daeb8a04c56b2c1d1702e312f88",
      "google-site-verification=sK6uY9x7eaMoEMfn3OILqwTFYgaNp4llmguKI-C3_iA",
      "google-site-verification=wdH5DTJTc9AYNwVunSVFeK0hYDGUIEOGb-RReU6pJlY",
      "v=spf1 redirect=_spf.facebook.com"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:a@dmarc.facebookmail.com; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_CHACHA20_POLY1305_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Menlo Park, organizationName=Meta Platforms, Inc., commonName=*.facebook.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jul  6 00:00:00 2026 GMT",
    "notAfter": "Oct  4 23:59:59 2026 GMT",
    "san": [
      "*.facebook.com",
      "*.facebook.net",
      "*.fbcdn.net",
      "*.fbsbx.com",
      "*.m.facebook.com",
      "*.messenger.com",
      "*.xx.fbcdn.net",
      "*.xy.fbcdn.net",
      "*.xz.fbcdn.net",
      "facebook.com",
      "messenger.com"
    ],
    "days_left": 8,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "57.144.92.1",
    "open": []
  },
  "https": {
    "status": 301,
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
      "origin": "https://sub.facebook.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://facebook.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 56,
    "notable": [
      "beta.facebook.com",
      "dev.facebook.com",
      "fb.beta.facebook.com",
      "hr.facebook.com",
      "interngraph.staging.scgraph.facebook.com",
      "m.beta.facebook.com",
      "secure.beta.facebook.com",
      "smtpin.mx.facebook.com",
      "staging.scgraph.facebook.com"
    ],
    "sample": [
      "alpha.facebook.com",
      "alpha.intern.facebook.com",
      "beta.facebook.com",
      "cstools.facebook.com",
      "dev.facebook.com",
      "dewey-lfs.vip.facebook.com",
      "dewey.vip.facebook.com",
      "extern.facebook.com",
      "facebook.com",
      "fb.alpha.facebook.com",
      "fb.beta.facebook.com",
      "fb.m.alpha.facebook.com",
      "h.facebook.com",
      "hr.facebook.com",
      "intern.facebook.com",
      "interngraph.prod.scgraph.facebook.com",
      "interngraph.scgraph.facebook.com",
      "interngraph.staging.scgraph.facebook.com",
      "internmc.facebook.com",
      "internmcr.facebook.com"
    ]
  },
  "apex_txt": [
    "zoom-domain-verification=4b2ef4e1-6dee-4483-9869-9bef353fd147",
    "google-site-verification=A2WZWCNQHrGV_TWwKh6KHY90tY0SHZo_RnyMJoDaG0s",
    "facebook-domain-verification=y7isfmi3kzyg1r4wophh9vyb6pgbda",
    "zoom-domain-verification=ZOOM_verify_e6c41daeb8a04c56b2c1d1702e312f88",
    "google-site-verification=sK6uY9x7eaMoEMfn3OILqwTFYgaNp4llmguKI-C3_iA"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260706000000",
      "not_after": "20261004235959"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/*/plugins/*",
      "/?*next=",
      "/a/bz?",
      "/ajax/",
      "/album.php",
      "/business/*&categories",
      "/business/*?categories",
      "/business/help/search*&query="
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "edge-star-mini-shv-01-tpe5.facebook.com."
    ]
  },
  "elapsed_s": 7.4,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
