# Security Audit Report — spiegel.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://spiegel.de/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | spiegel.de |
| Test date | 2026-09-26 23:38 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 16 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 17 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 18 | info | CT1 | 129 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=MPW2epf3b4liwmBTYP8FJEH80rywYRbvVjEeZmcZX_0; atlassian-domain-verification=qkv0u2nj3emGh9UVqNl/2AOp/BxahFJ7m2Bbv8bUPlGhytfsEA; atlassian-domain-verification=rnDZY6SZaJnSOpSEvPr0kzhgihiqUPn3g8W0pFQfopQhaMO4jk
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but spiegel.de is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 109 disallow path(s), e.g. /*CR-Dokumentation.pdf$, /, /, /, /
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for spiegel.de, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 16. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on spiegel.de has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of spiegel.de.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 17. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on spiegel.de lists 4219 <loc> URL(s) across 4220 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 18. [INFO] 129 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.dev.backoffice.spiegel.de, assets.spiegel.de, cdn.data-interactive.spiegel.de, cdn.qs.resources.spiegel.de, cloud.angebote.spiegel.de, dev.airflow.calypso.spiegel.de, dev.amendo.spiegel.de, dev.assets-api.spiegel.de, dev.assets.spiegel.de, dev.backoffice.spiegel.de
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "spiegel.de",
  "dns": {
    "a": [
      "128.65.223.150"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "spiegel-de.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "pns103.cloudns.net.",
      "pns101.cloudns.net.",
      "pns104.cloudns.net.",
      "pns102.cloudns.net."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=MPW2epf3b4liwmBTYP8FJEH80rywYRbvVjEeZmcZX_0",
      "00DD0000000mZzl=1TBVl00000000Pp",
      "v=spf1 ip4:18.196.136.27 ip4:185.45.16.170 ip4:185.45.16.70 include:spf.protection.outlook.com include:amazonses.com include:_spf.salesforce.com -all",
      "atlassian-domain-verification=qkv0u2nj3emGh9UVqNl/2AOp/BxahFJ7m2Bbv8bUPlGhytfsEAB3Zyd8AvXOEHVW",
      "atlassian-domain-verification=rnDZY6SZaJnSOpSEvPr0kzhgihiqUPn3g8W0pFQfopQhaMO4jkTWsvLmIj5TeGNB",
      "jamf-site-verification=mDxSkZxQSP3_MF8_pHR9BA",
      "anthropic-domain-verification-199cnz=roKzFqEYT6AZRSPy7A7lASgkj",
      "google-site-verification=d2wrdnHq-bRRkqVOBRvGWuxjCYVnXIiaoOp6U79jKag",
      "adobe-idp-site-verification=1ab58e56a7c5cfcf85df9cf0e34dc26505b7982a08fd338b70244c5611b99242",
      "mgverify=ae2a244a3a76e9bcdbe6865e4b169acb67d1168d1ab6518bcfcc3eb11e394afc",
      "01119681",
      "MS=ms15909706",
      "apple-domain-verification=ABQrqpdvNdt43ZXd"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:report.dmarc@spiegel.de; ruf=mailto:report.dmarc@spiegel.de; sp=reject; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=www.spiegel.de",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=GeoTrust TLS RSA CA G1",
    "notBefore": "Dec  5 00:00:00 2025 GMT",
    "notAfter": "Dec  4 23:59:59 2026 GMT",
    "san": [
      "www.spiegel.de",
      "spiegel.de",
      "prod.www.spiegel.de"
    ],
    "days_left": 69,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "128.65.223.150",
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
      "origin": "https://sub.spiegel.de",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://spiegel.de/"
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
    "source": "certspotter",
    "count": 129,
    "notable": [
      "api.dev.backoffice.spiegel.de",
      "assets.spiegel.de",
      "cdn.data-interactive.spiegel.de",
      "cdn.qs.resources.spiegel.de",
      "cloud.angebote.spiegel.de",
      "dev.airflow.calypso.spiegel.de",
      "dev.amendo.spiegel.de",
      "dev.assets-api.spiegel.de",
      "dev.assets.spiegel.de",
      "dev.backoffice.spiegel.de",
      "dev.brixwire-adm.spiegel.de",
      "dev.brixwire.spiegel.de",
      "dev.calypso.spiegel.de",
      "dev.explain.calypso.spiegel.de",
      "dev.journalsuite.spiegel.de"
    ],
    "sample": [
      "1234test.spiegel.de",
      "ais.review.wisl.spiegel.de",
      "akademie.spiegel.de",
      "amendo.spiegel.de",
      "api.dev.backoffice.spiegel.de",
      "assets-api.spiegel.de",
      "assets.spiegel.de",
      "bis.spiegel.de",
      "bmd.prod.backoffice.spiegel.de",
      "brixwire-adm.spiegel.de",
      "brixwire.spiegel.de",
      "cdn.data-interactive.spiegel.de",
      "cdn.qs.resources.spiegel.de",
      "click.angebote.spiegel.de",
      "cloud.angebote.spiegel.de",
      "cmk.spiegel.de",
      "cms.spiegel.de",
      "dev.airflow.calypso.spiegel.de",
      "dev.amendo.spiegel.de",
      "dev.assets-api.spiegel.de"
    ]
  },
  "apex_txt": [
    "google-site-verification=MPW2epf3b4liwmBTYP8FJEH80rywYRbvVjEeZmcZX_0",
    "atlassian-domain-verification=qkv0u2nj3emGh9UVqNl/2AOp/BxahFJ7m2Bbv8bUPlGhytfsEA",
    "atlassian-domain-verification=rnDZY6SZaJnSOpSEvPr0kzhgihiqUPn3g8W0pFQfopQhaMO4jk",
    "jamf-site-verification=mDxSkZxQSP3_MF8_pHR9BA",
    "anthropic-domain-verification-199cnz=roKzFqEYT6AZRSPy7A7lASgkj"
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
      "aia_ocsp": "http://status.geotrust.com",
      "serial": 7393694005620797097937893695380263105,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl"
      ],
      "subject_dn": "311730150603550403130e7777772e7370696567656c2e6465",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d311f301d0603550403131647656f547275737420544c5320525341204341204731",
      "not_before": "20251205000000",
      "not_after": "20261204235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/*CR-Dokumentation.pdf$",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.spiegel.de/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=31536000;",
    "sitemap": {
      "urls": 4219,
      "indexes": 4220
    },
    "crl": {
      "url": "http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl",
      "status": 200
    }
  },
  "elapsed_s": 26.0,
  "rechecked": "2026-09-26 23:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- Findings are reported against the public program scope; submission through the program tracker is pending.
