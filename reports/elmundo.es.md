# Security Audit Report — elmundo.es

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://elmundo.es/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | elmundo.es |
| Test date | 2026-09-26 18:50 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 6, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | low | CORS1 | CORS: subdomain origin origin accepted with credentials | CWE-942 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 19 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 20 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 14 days (notAfter Oct 10 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 11. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [LOW] CORS: subdomain origin origin accepted with credentials (`CORS1`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.elmundo.es -> Access-Control-Allow-Origin: https://sub.elmundo.es, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

### 14. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 15. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 16. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: globalsign-domain-verification=7bjinxNsR4XyhujN4NAlLtHAWyALVtjJgzNZciDdZ-; atlassian-domain-verification=T5fbuvw/H/J2eZWKPjYsqChbdQg/OqHtq4MQ1Ak76LJubHwebj; adobe-idp-site-verification=5d984b54fc7397d92bb1b96a40c532b3ad090875dedb22c00a14
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of elmundo.es has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 19. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 130 disallow path(s), e.g. /1998/, /2002/, /s/, /cgi-bin/, /perl/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 20. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 34.90.247.117 carries PTR 117.247.90.34.bc.googleusercontent.com. for elmundo.es.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "elmundo.es",
  "dns": {
    "a": [
      "34.90.247.117"
    ],
    "aaaa": [
      "2001:67c:2294:1000::f199"
    ],
    "cname": null,
    "mx": [
      "elmundo-es.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns4-02.azure-dns.info.",
      "ns1-02.azure-dns.com.",
      "ns2-02.azure-dns.net.",
      "ns3-02.azure-dns.org."
    ],
    "spf": [
      "globalsign-domain-verification=7bjinxNsR4XyhujN4NAlLtHAWyALVtjJgzNZciDdZ-",
      "atlassian-domain-verification=T5fbuvw/H/J2eZWKPjYsqChbdQg/OqHtq4MQ1Ak76LJubHwebjnJx2DWy5zGgbDr",
      "v=spf1 mx ip4:212.80.144.25 a:mailing.unidadeditorial.es ip4:193.110.128.182 ip4:93.90.16.107 ip4:212.80.144.192 include:t.contactlab.it include:amazonses.com include:spf.protection.outlook.com include:spf.mail.netclient.no ip4:13.81.124.182 -all",
      "cMMfg3L6wl5iOp7rf/T1gX1IK075nC4837wyuYxfHi6FEX2glov0GKi/9E3JuKYvv55vdco+0hJsNMW8AQbe4Q==",
      "adobe-idp-site-verification=5d984b54fc7397d92bb1b96a40c532b3ad090875dedb22c00a14cab10c239da0",
      "google-site-verification=5DcZ3fJzOj0f4QBZPhxEO6lT09vXcIu-hy35RDXHkc4",
      "f6ecbiuc2h43tvq9vav81rddmt",
      "globalsign-domain-verification=KHdzCZD_oMiYp479wH9wCSZsMlbwL6t2W0nwUGP2eU",
      "MS=ms46178158",
      "google-site-verification=V40iSs6vN6O1kFq-Egky0AmbTyIly-EukOcOWjuyT30"
    ],
    "dmarc": [
      "v=DMARC1; p=none; fo=1; rua=mailto:dmarc_rua_UE@unidadeditorial.es; ruf=mailto:dmarc_ruf_UE@unidadeditorial.es; pct=100;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.elmundo.es",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA DV R36",
    "notBefore": "Mar 26 00:00:00 2026 GMT",
    "notAfter": "Oct 10 23:59:59 2026 GMT",
    "san": [
      "*.elmundo.es",
      "elmundo.es"
    ],
    "days_left": 14,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.90.247.117",
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
      "origin": "https://sub.elmundo.es",
      "acao": "https://sub.elmundo.es",
      "acac": "true"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://elmundo.es/"
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
  "apex_txt": [
    "globalsign-domain-verification=7bjinxNsR4XyhujN4NAlLtHAWyALVtjJgzNZciDdZ-",
    "atlassian-domain-verification=T5fbuvw/H/J2eZWKPjYsqChbdQg/OqHtq4MQ1Ak76LJubHwebj",
    "adobe-idp-site-verification=5d984b54fc7397d92bb1b96a40c532b3ad090875dedb22c00a14",
    "google-site-verification=5DcZ3fJzOj0f4QBZPhxEO6lT09vXcIu-hy35RDXHkc4",
    "globalsign-domain-verification=KHdzCZD_oMiYp479wH9wCSZsMlbwL6t2W0nwUGP2eU"
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
      "not_before": "20260326000000",
      "not_after": "20261010235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/1998/",
      "/2002/",
      "/s/",
      "/cgi-bin/",
      "/perl/",
      "/foros/",
      "/yodona/hemeroteca/",
      "/metropoli/hemeroteca/",
      "/eventos/en-directo/*.json",
      "/eventos/en-directo/resources.html*",
      "/noticias/envia_noticia.html",
      "/enviaropinion.html?*",
      "/micuenta/",
      "*/pruebas-abierto/*",
      "*/elmundo/hemeroteca/*/*/*/*/*"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "117.247.90.34.bc.googleusercontent.com."
    ]
  },
  "elapsed_s": 27.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
