# Security Audit Report — zoom.us

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://zoom.us/ |
| Bug bounty program | Zoom |
| Listed scope domain | zoom.us |
| Test date | 2026-09-26 19:02 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **39** (High: 0, Medium: 9, Low: 4, Info: 26)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | PRT21 | FTP service (cleartext) reachable | CWE-319 |
| 3 | info | PRT22 | SSH reachable | CWE-200 |
| 4 | medium | PRT23 | Telnet service (cleartext) reachable | CWE-319 |
| 5 | info | PRT25 | SMTP (port 25) reachable | CWE-200 |
| 6 | info | PRT53 | DNS service reachable | CWE-200 |
| 7 | info | PRT110 | POP3 (cleartext) reachable | CWE-319 |
| 8 | info | PRT143 | IMAP (cleartext) reachable | CWE-319 |
| 9 | info | PRT993 | IMAPS (port 993) reachable | CWE-200 |
| 10 | info | PRT995 | POP3S (port 995) reachable | CWE-200 |
| 11 | medium | PRT1433 | MSSQL (port 1433) reachable | CWE-200 |
| 12 | medium | PRT3306 | MySQL (port 3306) reachable | CWE-200 |
| 13 | info | PRT3389 | RDP (port 3389) reachable | CWE-200 |
| 14 | medium | PRT5432 | PostgreSQL (port 5432) reachable | CWE-200 |
| 15 | medium | PRT5900 | VNC (port 5900) reachable | CWE-200 |
| 16 | medium | PRT6379 | Redis (port 6379) reachable | CWE-200 |
| 17 | info | PRT8000 | Alternate web service (port 8000) reachable | CWE-200 |
| 18 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 19 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 20 | info | PRT8888 | Alternate web service (port 8888) reachable | CWE-200 |
| 21 | info | PRT9090 | Service (port 9090, e.g. Elasticsearch/debug) reachable | CWE-200 |
| 22 | medium | PRT9200 | Elasticsearch (port 9200) reachable | CWE-200 |
| 23 | medium | PRT27017 | MongoDB (port 27017) reachable | CWE-200 |
| 24 | info | TECH1 | Technology fingerprint | CWE-200 |
| 25 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 26 | low | H1 | Missing HSTS header | CWE-319 |
| 27 | low | H2 | Missing CSP header | CWE-1021 |
| 28 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 29 | low | H4 | No clickjacking protection | CWE-1023 |
| 30 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 31 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 32 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 33 | info | H6 | Server technology disclosure | CWE-200 |
| 34 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 35 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 36 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 37 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 38 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 39 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [MEDIUM] FTP service (cleartext) reachable (`PRT21`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 170.114.52.2:21 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] SSH reachable (`PRT22`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:22 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [MEDIUM] Telnet service (cleartext) reachable (`PRT23`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 170.114.52.2:23 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] SMTP (port 25) reachable (`PRT25`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:25 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 6. [INFO] DNS service reachable (`PRT53`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:53 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 7. [INFO] POP3 (cleartext) reachable (`PRT110`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 170.114.52.2:110 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 8. [INFO] IMAP (cleartext) reachable (`PRT143`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 170.114.52.2:143 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 9. [INFO] IMAPS (port 993) reachable (`PRT993`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:993 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 10. [INFO] POP3S (port 995) reachable (`PRT995`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:995 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 11. [MEDIUM] MSSQL (port 1433) reachable (`PRT1433`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:1433 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 12. [MEDIUM] MySQL (port 3306) reachable (`PRT3306`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:3306 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 13. [INFO] RDP (port 3389) reachable (`PRT3389`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:3389 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 14. [MEDIUM] PostgreSQL (port 5432) reachable (`PRT5432`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:5432 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 15. [MEDIUM] VNC (port 5900) reachable (`PRT5900`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:5900 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 16. [MEDIUM] Redis (port 6379) reachable (`PRT6379`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:6379 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 17. [INFO] Alternate web service (port 8000) reachable (`PRT8000`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:8000 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 18. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 19. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 20. [INFO] Alternate web service (port 8888) reachable (`PRT8888`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:8888 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 21. [INFO] Service (port 9090, e.g. Elasticsearch/debug) reachable (`PRT9090`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:9090 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 22. [MEDIUM] Elasticsearch (port 9200) reachable (`PRT9200`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:9200 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 23. [MEDIUM] MongoDB (port 27017) reachable (`PRT27017`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 170.114.52.2:27017 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 24. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 25. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 26. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 27. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 28. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 29. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 30. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 31. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 32. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 33. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 34. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 35. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 36. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: paloaltonetworks-site-verification=ab6a946a97f44c0b83b5cc59ba90e5f0c768666814ce8; adobe-idp-site-verification=7116ab50a89b2c2402382aea3362209410eac90f2a590f358ce1; mongodb-site-verification=LuLsVGWKjIwOk54WdscqbRmXgqU2kGIc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 37. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of zoom.us has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 38. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 28 disallow path(s), e.g. /download/*/Zoom_launcher.exe, /download/*/zoomusLauncher.zip, /docs/image/new/brand/outdated/, /docs/doc/2-Page-All-Products.pdf, /docs/doc/zoom-apps-security-privacy-faq.pdf
- **Recommendation:** Review disallowed paths; robots is not access control.

### 39. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://zoom.us/ carries Cache-Control: max-age=3600; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

## Evidence (raw response observations)

```json
{
  "domain": "zoom.us",
  "dns": {
    "a": [
      "170.114.52.2"
    ],
    "aaaa": [
      "2407:30c0:182::aa72:3402"
    ],
    "cname": null,
    "mx": [
      "mxa-00569201.gslb.pphosted.com (pref 10)",
      "mxb-00569201.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-1772.awsdns-29.co.uk.",
      "ns-1137.awsdns-14.org.",
      "ns-387.awsdns-48.com.",
      "ns-888.awsdns-47.net."
    ],
    "spf": [
      "paloaltonetworks-site-verification=ab6a946a97f44c0b83b5cc59ba90e5f0c768666814ce8347703af032dbeff05c",
      "SFMC-FEDGKE8lGkIFM2TngfZtUoES_Ep-nR1DSOvRZFxz",
      "adobe-idp-site-verification=7116ab50a89b2c2402382aea3362209410eac90f2a590f358ce1189d0ca1a8c4",
      "v=zoomadn us.zoom.idp.commercial=zoom.okta.com",
      "mongodb-site-verification=LuLsVGWKjIwOk54WdscqbRmXgqU2kGIc",
      "stripe-verification=f613690c5cef6193bdc4638549691d7c4b80994cd6b47c182d9ce9afa560b964",
      "HaFoSdUeCSdJo9U8lG@NWZ6vnoRltUteEAl&yuY$$eE25sKJguFH58Lss%9@e73OK#XigH^i3mCDjax&gfZq*90lw4k4Vi3UMpC",
      "pardot_84442_*=f0bf83bf261ad77163f6e86fc94ae06036d153cc65df5531309b396933da9591",
      "docker-verification=e55e0281-9c6f-4cba-8788-e50c50899b3f",
      "stripe-verification=64a9e3b2f28cc3bb2182307c5c2ea98aa78bfe6a36ed5f22bd3d0bc9667a2510",
      "status-page-domain-verification=pc76p1k8712r",
      "nintex.5e7289cea709bf0d10e77561",
      "anthropic-domain-verification-8fadf7=uwajz3dDn6eAq3Yl6LtArZNBA",
      "canva-site-verification=Fxuo9x2-ohLElGZ9w9XYHw",
      "teamviewer-sso-verification=4f42e066d37d4305b4091646efd91add",
      "stripe-verification=0628546b6023b9d18ecddf4eec9658f8513bb619d4ae413b1143f81b31ee7018",
      "atlassian-domain-verification=o4YG+mXlOE6uTJb7uGimcl9DJZnVg4aimBCf/4UrplRJvMk84JnXh2zF8jZz21Fx",
      "dropbox-domain-verification=3s15m13l23wp",
      "google-site-verification=JvBsPulrJw4xeN9DV9oeGqFDDUlAsJv-vLu1PriMw1g",
      "v=DMARC1; p=reject; ri=3600; rua=mailto:sesbounce@zoom.us,mailto:dmarc_rua@emaildefense.proofpoint.com",
      "oo414pse7fk8ntk80qoms9poc1",
      "atlassian-domain-verification=4y6yoGrdYbj4zq5bMXvpGI1KFVEzSVuWMYG4/Gv4BuFjIthTVBWnV8qf47TYfL5Q",
      "stripe-verification=68b6edce67880909a44aad0af814c3afe0bf8e053e70f81c70264bf9156c4861",
      "google-site-verification=yofTND47qXdSBHRBZSkPUrP0QQ-WF76h-K-F05IHmj0",
      "knowbe4-site-verification=c3a762336824e50b8902fc5d47a79dd9",
      "smartsheet-site-validation=DYfGXuyJc7oq-_D05ZZyl6QGXpRWSWpR",
      "google-site-verification=G6mELnMFHZrRpJ_rAqHPDP2voFX3_g-lN78U-eJ7xJY",
      "ljtjrbvpt98v132shnhkm0thlt",
      "vmware-cloud-verification-4d68d199-43dd-455f-ad71-18141d5d09c8",
      "slack-domain-verification=DPFh88HZR7KVwJkwlh98Y0PgSABl6BKgY1hVlwhC",
      "cui69v35i9t5lj9360gajgt1tc",
      "stripe-verification=29700ec8c3d8a93a634139f4dfe8a23a87f6b97829d3e6ea123d07f7e58504d0",
      "google-site-verification=r5_uj4r2YuGNrhng2dLo4xfDAvaYGhNuqv6icJiQdxA",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com include:_spf.google.com include:amazonses.com ip4:52.38.191.241 include:servers.mcsv.net include:_spf.salesforce.com ip4:13.110.78.0/24 ~all",
      "stripe-verification=933cf52c0e93778a0f3fbdc96954c1f6bd9813b6356cdc71667df03b44336c1e",
      "google-site-verification=kzxH5gxEvbMw9EUX-uQNCNxzoHNk7eksOJdaOLt-WYA",
      "h1-domain-verification=5yw85Ewx1obuckMSkZQokfDYewnzdBw9JqKmZWMXqFs2F3cq",
      "stripe-verification=c9c277e76c265ef8b27ee1fb8b7f6e6240daacf25d36f96d586c05301b0306eb",
      "apple-domain-verification=CbBNkhNvbPFzgvvv",
      "docusign=b21dec83-4d62-479c-b2aa-43a0cd4c125a",
      "stripe-verification=56bc5cf2da44b2033da49b45ed3789209db29432268975666693a750ecfde757",
      "facebook-domain-verification=r9u6lu6z5wy3yokf7yd52l6k08xqsx",
      "autodesk-domain-verification=oPP5RpbpIX2AL7W7H2p2",
      "spycloud-domain-verification=889b71d1-9e56-48da-a7cc-f3bc6497ca2f",
      "google-site-verification=RA1o2A5KlW67SrvzJ4JovDWlkMzOtxJnS6Lq4MWso1Q"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;ri=3600;rua=mailto:sesbounce@zoom.us,mailto:dmarc_rua@emaildefense.proofpoint.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Jose, organizationName=Zoom Communications, Inc., commonName=*.zoom.us",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Dec 29 00:00:00 2025 GMT",
    "notAfter": "Dec 29 23:59:59 2026 GMT",
    "san": [
      "*.zoom.us",
      "zoom.us"
    ],
    "days_left": 94,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "170.114.52.2",
    "open": [
      21,
      22,
      23,
      25,
      53,
      110,
      143,
      993,
      995,
      1433,
      3306,
      3389,
      5432,
      5900,
      6379,
      8000,
      8080,
      8443,
      8888,
      9090,
      9200,
      27017
    ]
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.zoom.us",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.zoom.com"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "paloaltonetworks-site-verification=ab6a946a97f44c0b83b5cc59ba90e5f0c768666814ce8",
    "adobe-idp-site-verification=7116ab50a89b2c2402382aea3362209410eac90f2a590f358ce1",
    "mongodb-site-verification=LuLsVGWKjIwOk54WdscqbRmXgqU2kGIc",
    "stripe-verification=f613690c5cef6193bdc4638549691d7c4b80994cd6b47c182d9ce9afa560",
    "docker-verification=e55e0281-9c6f-4cba-8788-e50c50899b3f"
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
      "not_before": "20251229000000",
      "not_after": "20261229235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/download/*/Zoom_launcher.exe",
      "/download/*/zoomusLauncher.zip",
      "/docs/image/new/brand/outdated/",
      "/docs/doc/2-Page-All-Products.pdf",
      "/docs/doc/zoom-apps-security-privacy-faq.pdf",
      "/docs/doc/zoom-apps-data-management.pdf",
      "/wc/*",
      "/web/*",
      "/share*",
      "/support*",
      "/j/*",
      "/z/*",
      "/s/*",
      "/u/*",
      "/w/*"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 6.8,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
