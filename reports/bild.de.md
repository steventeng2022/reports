# Security Audit Report — bild.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bild.de/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | bild.de |
| Test date | 2026-09-26 18:46 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 5, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=wSGR6qpcbZeGKdQUKg6ipsQj_7AeNxrPHVEcIiWgpRE; tollbit-domain-verification=ef1aafa3100448786098f1b0fd1cf9c371f06a3d95599485935c; openai-domain-verification=dv-QcSSDilElWZgs6xle7DozExl
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of bild.de has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 26 disallow path(s), e.g. /, /partner/, /jobs/api/gmapi, /community/, /sonstiges/vorproduktion/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.210.215.203 carries PTR a23-210-215-203.deploy.static.akamaitechnologies.com. for bild.de.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "bild.de",
  "dns": {
    "a": [
      "23.210.215.203",
      "23.210.215.218"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "bild-de.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "a16-65.akam.net.",
      "a6-66.akam.net.",
      "a1-130.akam.net.",
      "a11-67.akam.net.",
      "a7-67.akam.net.",
      "a14-64.akam.net."
    ],
    "spf": [
      "google-site-verification=wSGR6qpcbZeGKdQUKg6ipsQj_7AeNxrPHVEcIiWgpRE",
      "tollbit-domain-verification=ef1aafa3100448786098f1b0fd1cf9c371f06a3d95599485935c0f8014c36dc7",
      "openai-domain-verification=dv-QcSSDilElWZgs6xle7DozExl",
      "v=spf1 include:spf.asv.de include:spf.protection.outlook.com include:em6919.bild.de a:static.85-10-194-80.clients.your-server.de ?all",
      "_7zhs4nhu5pu1abphvwem9ivimuxjuth",
      "google-site-verification=GIwP8nvMGCphDvQq77TEZC32YbjuCGwW4sSunpEYSlk",
      "QFpSE9bKoWuwVmDnsk9WcN2uDM+gd4XFp4U+KOUCJ/dZ6a2PymbU3qNhP8lsAMC0k2ClaLcBIjPCEDASk8XO6A==",
      "pulvcolf3k6tosp096g2c9q9jo",
      "google-site-verification=0uD0nmX-Cw8fSCHOlf_TfTZRyXjOPNih1lRM3L1jC0Q",
      "adobe-idp-site-verification=62bcde131337d67652c5065053b7b1bf966f7bb65d0b3b51fdbe1ca653239533",
      "MS=ms99535522",
      "eqtr0qnhkpp5vj7krpo4ai3g3n",
      "figma-domain-verification=0a2753e7829cecbb7be239a2021677e64fb8c3603b24e4bb473e7cf21d9a351b-1787909594"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=none; rua=mailto:dmarc-rua@dkim10888.de; ruf=mailto:dmarc-ruf@dkim10888.de"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=DE, stateOrProvinceName=Berlin, localityName=Berlin, organizationName=Axel Springer SE, commonName=www.bild.de",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=GeoTrust TLS RSA CA G1",
    "notBefore": "Dec 24 00:00:00 2025 GMT",
    "notAfter": "Jan 24 23:59:59 2027 GMT",
    "san": [
      "www.bild.de",
      "www.wintersport.bild.de",
      "www.storage.projects.bild.de",
      "wintersport.sportbild.bild.de",
      "storage.projects.bild.de",
      "storage.partner.bild.de",
      "storage.bildplus.de",
      "sportdaten.sportbild.bild.de",
      "partner.storage.bild.de",
      "neukundenangebote.bildplus.de",
      "m.wetter.bild.de",
      "m.tv.bild.de",
      "m.sportdaten.sportbild.bild.de",
      "m.sportbild.bild.de",
      "m.sport.bild.de",
      "liveticker.sportbild.bild.de",
      "download.storage.bild.de",
      "bild.de",
      "*.bildstatic.de",
      "*.bild.leancms.de",
      "*.bild.de"
    ],
    "days_left": 120,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.210.215.203",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.bild.de",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://bild.de/"
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
    "google-site-verification=wSGR6qpcbZeGKdQUKg6ipsQj_7AeNxrPHVEcIiWgpRE",
    "tollbit-domain-verification=ef1aafa3100448786098f1b0fd1cf9c371f06a3d95599485935c",
    "openai-domain-verification=dv-QcSSDilElWZgs6xle7DozExl",
    "google-site-verification=GIwP8nvMGCphDvQq77TEZC32YbjuCGwW4sSunpEYSlk",
    "google-site-verification=0uD0nmX-Cw8fSCHOlf_TfTZRyXjOPNih1lRM3L1jC0Q"
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
      "not_before": "20251224000000",
      "not_after": "20270124235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/partner/",
      "/jobs/api/gmapi",
      "/community/",
      "/sonstiges/vorproduktion/",
      "/test_stage/",
      "/test/",
      "/energieloesungen/*-form/",
      "/energieloesungen/social/*-form/",
      "/energieloesungen/vergleich/*-form/",
      "/leben-im-alter/*-form/",
      "/cmsid/",
      "/jobs/api/gmapi",
      "/community/",
      "/sonstiges/vorproduktion/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a23-210-215-203.deploy.static.akamaitechnologies.com."
    ]
  },
  "elapsed_s": 7.8,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
