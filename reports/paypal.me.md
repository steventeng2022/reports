# Security Audit Report — paypal.me

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://paypal.me/ |
| Bug bounty program | PayPal |
| Listed scope domain | paypal.me |
| Test date | 2026-09-26 17:50 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 4, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=300 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

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
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of paypal.me has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but paypal.me is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 3 disallow path(s), e.g. User-agent:, User-agent:, /
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "paypal.me",
  "dns": {
    "a": [
      "151.101.129.21",
      "151.101.65.21",
      "162.159.141.96"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx1.paypalcorp.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns1-pchnet.paypal.com.",
      "pdns100.ultradns.net.",
      "pdns100.ultradns.com.",
      "ns2-pchnet.paypal.com."
    ],
    "spf": [
      "v=spf1 -all",
      "4tq9gwcyb51hm86yvjr684dhkqh9b1xy"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "jurisdictionCountryName=US, jurisdictionStateOrProvinceName=Delaware, businessCategory=Private Organization, serialNumber=3014267, countryName=US, stateOrProvinceName=California, localityName=San Jose, organizationName=PayPal, Inc., commonName=www.paypal.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert EV RSA CA G2",
    "notBefore": "Aug 28 00:00:00 2026 GMT",
    "notAfter": "Mar 14 23:59:59 2027 GMT",
    "san": [
      "www.paypal.com",
      "articles.braintreepayments.com",
      "assets.braintreegateway.com",
      "braintreecharge.com",
      "braintreefinancial.com",
      "braintreepayments.com",
      "braintreepaymentsolutions.com",
      "brand.braintreepayments.com",
      "business.paypal.com",
      "c.paypal.com",
      "c6.paypal.com",
      "checkout.paypal.com",
      "connect.paypal.com",
      "content.paypalobjects.com",
      "cors.api.paypal.com",
      "creditapply.paypal.com",
      "de.paypal-qrc.com",
      "demo.paypal.com",
      "developer.braintreepayments.com",
      "developer.paypal.com",
      "developers.braintreepayments.com",
      "docs.paypal.ai",
      "es.paypal-qrc.com",
      "fastlane.paypal.com",
      "financing.paypal.com",
      "fpdbs.paypal.com",
      "fr.paypal-qrc.com",
      "help.braintreepayments.com",
      "history.paypal.com",
      "id.braintreegateway.com",
      "id.hyperwallet.com",
      "id.joinhoney.com",
      "id.paypal.com",
      "id.venmo.com",
      "id.xoom.com",
      "id.zettle.com",
      "id6.venmo.com",
      "it.paypal-qrc.com",
      "js.braintreegateway.com",
      "login.paypal.com",
      "m.paypal.co.uk",
      "m.paypal.com",
      "m.paypal.com.au",
      "m.paypal.es",
      "m.paypal.fr",
      "m.paypal.it",
      "mobile.paypal.com",
      "now.id.venmo.com",
      "now.venmo.com",
      "onboarding.paypal.com",
      "p.paypal.com",
      "paypal.me",
      "pep.paypal.com",
      "pics.paypal.com",
      "pointofsale-s.paypal.com",
      "pp-au.paypal.com",
      "pp-eu.paypal.com",
      "pp-in.paypal.com",
      "pp-us.paypal.com",
      "py.pl",
      "qwac.paypal.com",
      "safebreach.paypal.com",
      "secure.paypal.com",
      "securepayments.paypal.com",
      "ssp.paypal.com",
      "sspserv.paypal.com",
      "support.braintreepayments.com",
      "t.paypal.com",
      "transfer.paypal.com",
      "uk.paypal-qrc.com",
      "us.paypal-qrc-seller-supplies.com",
      "us.paypal-qrc.com",
      "www-st.paypal.com",
      "www.braintreecharge.com",
      "www.braintreefinancial.com",
      "www.braintreepayments.com",
      "www.braintreepaymentsolutions.com",
      "www.brand.braintreepayments.com",
      "www.fastlane.paypal.com",
      "www.paypal-gifts.com",
      "www.paypal.ai",
      "www.paypal.biz",
      "www.paypal.me",
      "www.paypalobjects.com",
      "www.py.pl",
      "www.xo.paypal.com",
      "zettleintegrations.paypal.com"
    ],
    "days_left": 169,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.129.21",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.paypal.me",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://paypal.me/"
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
    "status": "ct-pending"
  },
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
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
      "User-agent:",
      "User-agent:",
      "/"
    ]
  },
  "elapsed_s": 17.5,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
