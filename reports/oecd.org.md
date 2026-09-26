# Security Audit Report — oecd.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://oecd.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | oecd.org |
| Test date | 2026-09-26 18:56 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 10 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 11 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 12 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 13 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 16 | info | CT1 | 124 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 17 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 10. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 11. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=SDEWojQdWXNif-TLtOo9erhxfQLpv29GSU6XhHK1r68; hpe-greenlake-domain-verification=4677486a4449536d6173586553475a59354f6761314d47; cisco-ci-domain-verification=295dc971d1c6be2b5403477737c89eac7ec07601440a1e0855e
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 12. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of oecd.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 13. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but oecd.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 2 disallow path(s), e.g. /content/dam/oecd/, /adobe/dynamicmedia/deliver/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://oecd.org/ carries Cache-Control: max-age=300; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 16. [INFO] 124 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.oecd.org, api.one-pp.oecd.org, api.one.oecd.org, login.my.oecd.org, login.oecd.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 17. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: login.my.oecd.org; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "oecd.org",
  "dns": {
    "a": [
      "151.101.3.10",
      "151.101.67.10",
      "151.101.195.10",
      "151.101.131.10"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "oecd-org.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns3-03.azure-dns.org.",
      "ns4-03.azure-dns.info.",
      "ns1-03.azure-dns.com.",
      "ns2-03.azure-dns.net."
    ],
    "spf": [
      "v=spf1 ip4:78.41.128.0/22 include:spf.protection.outlook.com -all",
      "_c4vs31pucag8knkqzie5i90hhnstnug",
      "2b065714-2fc1-4d13-b11f-08fbc02c7626",
      "google-site-verification=SDEWojQdWXNif-TLtOo9erhxfQLpv29GSU6XhHK1r68",
      "hpe-greenlake-domain-verification=4677486a4449536d6173586553475a59354f6761314d47683048313635694334",
      "d122tnk0lmcb7fw4lzdcvqmw9jdf4qqb",
      "docusign=26a8c1aa-ac33-45f2-9a60-8d2cd96d4b3d",
      "cisco-ci-domain-verification=295dc971d1c6be2b5403477737c89eac7ec07601440a1e0855e475c20aa08f68",
      "adobe-idp-site-verification=fe3732a56cceead6122113a39f9385a693c3367314cdad48789e5cfbf77d5977",
      "openai-domain-verification=dv-TmLkx83mPP4k3cYF7dEcKasX",
      "docusign=4a7be657-e630-44fc-87ba-b68287ac2a3d",
      "apple-domain-verification=Z7TTmRtTMuoxrVa2",
      "google-site-verification=ywMTwu2FAsfR60NR80rZ3jMdv8Ku-rr1NVnMGvor75k",
      "MS=ms12713444",
      "3f6aa5c46d2a4da482b5cb56af96dec1",
      "v/l2fKfgQ+sfAM7ZccgEU41dgW0s412pftzTh7XJzyim4AUo1Wi2WVai364FALz09lut6gJWcS8YLtAjbkatrA=="
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:mailincidentreport@oecd.org; ruf=mailto:mailincidentreport@oecd.org; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=FR, localityName=Paris, organizationName=Organisation for Economic Co-operation and Development, commonName=*.oecd.org",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Oct 16 00:00:00 2025 GMT",
    "notAfter": "Nov 16 23:59:59 2026 GMT",
    "san": [
      "*.oecd.org",
      "oecd.org"
    ],
    "days_left": 51,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.3.10",
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
      "origin": "https://sub.oecd.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://oecd.org/"
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
    "/server-status": 403,
    "/api/": 301
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 124,
    "notable": [
      "api.oecd.org",
      "api.one-pp.oecd.org",
      "api.one.oecd.org",
      "login.my.oecd.org",
      "login.oecd.org"
    ],
    "sample": [
      "algobank-pp.oecd.org",
      "algobank.oecd.org",
      "aopkb.oecd.org",
      "api-dev.oecd.org",
      "api-pp.oecd.org",
      "api-st.oecd.org",
      "api.oecd.org",
      "api.one-pp.oecd.org",
      "api.one.oecd.org",
      "bo.oecd.org",
      "co.westernbalkans-competitiveness.oecd.org",
      "community.oecd.org",
      "cts-test-digicert.oecd.org",
      "cts-test-entrust.oecd.org",
      "cts-test-globalsign.oecd.org",
      "cts-test-thawte.oecd.org",
      "data-explorer-pp.oecd.org",
      "data-explorer.oecd.org",
      "data-viewer-pp.oecd.org",
      "data-viewer.oecd.org"
    ],
    "dangling": [
      "login.my.oecd.org"
    ]
  },
  "apex_txt": [
    "google-site-verification=SDEWojQdWXNif-TLtOo9erhxfQLpv29GSU6XhHK1r68",
    "hpe-greenlake-domain-verification=4677486a4449536d6173586553475a59354f6761314d47",
    "cisco-ci-domain-verification=295dc971d1c6be2b5403477737c89eac7ec07601440a1e0855e",
    "adobe-idp-site-verification=fe3732a56cceead6122113a39f9385a693c3367314cdad48789e",
    "openai-domain-verification=dv-TmLkx83mPP4k3cYF7dEcKasX"
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
      "not_before": "20251016000000",
      "not_after": "20261116235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/content/dam/oecd/",
      "/adobe/dynamicmedia/deliver/"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 25.5,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
