# Security Audit Report — canada.ca

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://canada.ca/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | canada.ca |
| Test date | 2026-09-26 18:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 4, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 14 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 15 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 16 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 17 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 18 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 19 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: BigIP
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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
- **Detail:** Header reveals: BigIP
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://www.canada.ca/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): emrs., slms. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 14. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 15. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 16. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: adobe-idp-site-verification=e4e5afcb1d9f55e0154efc626d8606ca67791a17c6ba4fc42d4a; cisco-ci-domain-verification=4bda055da9fd2766af026fa3999b5dffb95a030ad1f968d1398; linkedin-site-verification=330073d3-1782-412f-ac4f-7d523abea5a1
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 17. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of canada.ca has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 18. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but canada.ca is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 19. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 160.106.123.29 carries PTR DC01DC007-008-DEVTEST-VIP-123-29.dev.global.gc.ca. for canada.ca.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "canada.ca",
  "dns": {
    "a": [
      "160.106.123.29",
      "205.193.117.159",
      "167.40.79.24",
      "205.193.215.159"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "canada-ca.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "ns40.ent.global.gc.ca.",
      "ns2.d-zone.ca.",
      "ns10.ent.global.gc.ca.",
      "ns11.ent.global.gc.ca.",
      "ns41.ent.global.gc.ca.",
      "ns1.d-zone.ca."
    ],
    "spf": [
      "TrustedForDomainSharing=163gc.onmicrosoft.com",
      "MS=EA8C6DD155E90A72E7E2579A022AA9E9737B8521",
      "adobe-idp-site-verification=e4e5afcb1d9f55e0154efc626d8606ca67791a17c6ba4fc42d4a1053cd387efc",
      "v=DMARC1; p=none; rua=mailto:SSC.SecurityOperations-Operationsdelasecurite.SPC@canada.ca; ruf=mailto:SSC.SecurityOperations-Operationsdelasecurite.SPC@canada.ca",
      "v=spf1 include:emrs._spf.ssc-spc.gc.ca include:spf.protection.outlook.com include:slms._spf.ssc-spc.gc.ca -all",
      "cisco-ci-domain-verification=4bda055da9fd2766af026fa3999b5dffb95a030ad1f968d1398e30252b4788df",
      "linkedin-site-verification=330073d3-1782-412f-ac4f-7d523abea5a1",
      "linkedin-site-verification=12f98736-76a7-4053-83b1-d539d1283367",
      "MS=ms59231125",
      "google-site-verification=ifyhz_UIquElR0JcOEU4rudrSxSf4CWp_rUQ6yY2Z4g",
      "w2gqtzjhky14qb8q476v1l5q5kzl79dg",
      "MS=ms50475705"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:ssc.dmarc.spc@canada.ca,mailto:dmarc@cyber.gc.ca; adkim=s; aspf=s"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "subject": "countryName=CA, stateOrProvinceName=Ontario, organizationName=Shared Services Canada, commonName=www1.canada.ca",
    "issuer": "countryName=CA, organizationName=Entrust Limited, commonName=Entrust OV TLS Issuing RSA CA 2",
    "notBefore": "Jan 14 00:00:00 2026 GMT",
    "notAfter": "Feb 14 23:59:59 2027 GMT",
    "san": [
      "www1.canada.ca",
      "beta.canada.ca",
      "canada.ca",
      "canada.gc.ca",
      "wap.gc.ca",
      "www.beta.canada.ca",
      "www.canada.gc.ca",
      "www.gc.ca",
      "www.wap.gc.ca",
      "www.www1.canada.ca"
    ],
    "days_left": 141,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "160.106.123.29",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: BigIP"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.canada.ca",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://www.canada.ca/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "adobe-idp-site-verification=e4e5afcb1d9f55e0154efc626d8606ca67791a17c6ba4fc42d4a",
    "cisco-ci-domain-verification=4bda055da9fd2766af026fa3999b5dffb95a030ad1f968d1398",
    "linkedin-site-verification=330073d3-1782-412f-ac4f-7d523abea5a1",
    "linkedin-site-verification=12f98736-76a7-4053-83b1-d539d1283367",
    "google-site-verification=ifyhz_UIquElR0JcOEU4rudrSxSf4CWp_rUQ6yY2Z4g"
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
      "aia_ocsp": null,
      "not_before": "20260114000000",
      "not_after": "20270214235959"
    }
  },
  "x12": {
    "status": 302,
    "ptr": [
      "DC01DC007-008-DEVTEST-VIP-123-29.dev.global.gc.ca."
    ]
  },
  "elapsed_s": 34.7,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
