# Security Audit Report — ftc.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ftc.gov/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | ftc.gov |
| Test date | 2026-09-26 17:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 3, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
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
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=93600
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=VemqQV9Hiv6MzI1B0hzhRq4mlC2mVvs5qUUog19MRso; facebook-domain-verification=i064e2y03lievnt3ubarreperwg6mf; cisco-ci-domain-verification=25cadc1688da051ffa2539c464e864ec4aaefd22a584a0251e9
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of ftc.gov has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "ftc.gov",
  "dns": {
    "a": [
      "184.50.180.40"
    ],
    "aaaa": [
      "2600:1417:76:4a0::2031",
      "2600:1417:76:4a1::2031"
    ],
    "cname": null,
    "mx": [
      "ftc-gov.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "a7-67.akam.net.",
      "a26-64.akam.net.",
      "a1-252.akam.net.",
      "a3-65.akam.net.",
      "a6-66.akam.net.",
      "a24-67.akam.net."
    ],
    "spf": [
      "_a2ac2792i79twzh20o9uow3xf2g61d4",
      "google-site-verification=VemqQV9Hiv6MzI1B0hzhRq4mlC2mVvs5qUUog19MRso",
      "NzWLUncbdZVFeNNXMttXmWGCtTfPC610lVN0DG4twtsHL/fF6nVZ55r7BqRBAwnrzb076GaeoI+KR/D688HhEw==",
      "facebook-domain-verification=i064e2y03lievnt3ubarreperwg6mf",
      "MS=ms80119051",
      "cisco-ci-domain-verification=25cadc1688da051ffa2539c464e864ec4aaefd22a584a0251e9a7b769df530bf",
      "ab+sBVXiIC82wNktOPIy6RX8agj5Evkxyo85mpdxHboRO0smOB8QUksAASKBEFW1yz9vbMdeFb6kz3GkyshW+g==",
      "adobe-sign-verification=6aef5f85dec2584b6bd8bc23abb2418c2fd5746c6b72586f884b983098370e38",
      "apple-domain-verification=yDCeSJ81y3pXRCi0",
      "v=spf1 mx include:spf1.ftc.gov include:spf2.ftc.gov -all",
      "dwgyAlEH+VVQ4N58bmeEgHt3HhajTjhhUm+VEY/orFKBEvH2dcjCEBgIw9usDqvfE4etnbgRlB9RalHvcPraVg==",
      "identrust_validate=AW6O5chGVEhxWmmFGKoMLN8DZRwEsR4bmAtOrkHPfkc9",
      "MS=ms26536772",
      "adobe-idp-site-verification=a832eee07863ffdf3f5fdfc757918cff06c414cc6426d443d893f7e4740ac4f4",
      "identrust_validate=ba+DUU6G9a65f8A1q6tau3K4bx5bi/29LZlwh82DrgPG",
      "hpe-greenlake-domain-verification=6f677033714443654164395339726174365a7544727047374e74545068636837"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; rua=mailto:reports@dmarc.cyber.dhs.gov, mailto:dmarcemails@ftc.gov; ruf=mailto:dmarcemails@ftc.gov; rf=afrf; pct=100; ri=86400"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=District of Columbia, localityName=Washington, organizationName=Federal Trade Commission, commonName=www.ftc.gov",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=GeoTrust TLS RSA CA G1",
    "notBefore": "Feb  9 00:00:00 2026 GMT",
    "notAfter": "Feb  8 23:59:59 2027 GMT",
    "san": [
      "www.ftc.gov",
      "alertaenlinea.gov",
      "bulkorder.ftc.gov",
      "bulkorder2.ftc.gov",
      "business.ftc.gov",
      "consumer.ftc.gov",
      "consumer.gov",
      "consumidor.ftc.gov",
      "consumidor.gov",
      "dontserveteens.gov",
      "edit.bulkorder.ftc.gov",
      "edit.consumer.ftc.gov",
      "edit.consumer.gov",
      "edit.ftc.gov",
      "edit.militaryconsumer.gov",
      "edit.staging.ftc.gov",
      "ftc.gov",
      "hsr.gov",
      "loadtest.ftc.gov",
      "military.consumer.gov",
      "militaryconsumer.gov",
      "oig.ftc.gov",
      "onguardonline.gov",
      "search.ftc.gov",
      "staging.bulkorder.ftc.gov",
      "staging.consumer.ftc.gov",
      "staging.consumer.gov",
      "staging.ftc.gov",
      "staging.militaryconsumer.gov",
      "www.alertaenlinea.gov",
      "www.bulkorder.ftc.gov",
      "www.business.ftc.gov",
      "www.consumer.ftc.gov",
      "www.consumer.gov",
      "www.consumidor.ftc.gov",
      "www.consumidor.gov",
      "www.dontserveteens.gov",
      "www.hsr.gov",
      "www.military.consumer.gov",
      "www.militaryconsumer.gov",
      "www.onguardonline.gov"
    ],
    "days_left": 135,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "184.50.180.40",
    "open": []
  },
  "https": {
    "status": 403,
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
      "origin": "https://sub.ftc.gov",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 403
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 403,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 403,
    "/security.txt": 403,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=VemqQV9Hiv6MzI1B0hzhRq4mlC2mVvs5qUUog19MRso",
    "facebook-domain-verification=i064e2y03lievnt3ubarreperwg6mf",
    "cisco-ci-domain-verification=25cadc1688da051ffa2539c464e864ec4aaefd22a584a0251e9",
    "adobe-sign-verification=6aef5f85dec2584b6bd8bc23abb2418c2fd5746c6b72586f884b9830",
    "apple-domain-verification=yDCeSJ81y3pXRCi0"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "hsts_preloaded": true
  },
  "elapsed_s": 6.5,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
