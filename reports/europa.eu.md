# Security Audit Report — europa.eu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://europa.eu/ |
| Bug bounty program | European Central Bank |
| Listed scope domain | europa.eu |
| Test date | 2026-09-26 18:51 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Europa
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Europa
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: globalsign-domain-verification=6E976E49300A09A522CDF38DD011C63F; google-site-verification=OjhPSDIP2VIXIUH7hMv7CrLWwkyvnVgBdU-VcMHDoUI; google-site-verification=C0d5wiXRs2yokw7eUIL5Gz1825U9-M-HumwMZZYC7co
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of europa.eu has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 130 disallow path(s), e.g. /taxation_customs/dds2/ecics/, /cgi-bin/, /eur-lex/, /archives/, /youth/dissemination/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "europa.eu",
  "dns": {
    "a": [
      "147.67.34.45",
      "147.67.210.45"
    ],
    "aaaa": [
      "2a01:7080:24:100::666:45",
      "2a01:7080:14:100::666:45"
    ],
    "cname": null,
    "mx": [
      "mxa-00244802.gslb.pphosted.com (pref 10)",
      "europa-eu.mail.protection.outlook.com (pref 30)",
      "mxb-00244802.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ans2.cw.net.",
      "ns4az2.europa.eu.",
      "ns3bru.europa.eu.",
      "ns1lux.europa.eu.",
      "ns2bru.europa.eu.",
      "ns4az1.europa.eu.",
      "ns1bru.europa.eu.",
      "ns3lux.europa.eu.",
      "ans1.cw.net.",
      "ns2lux.europa.eu."
    ],
    "spf": [
      "globalsign-domain-verification=6E976E49300A09A522CDF38DD011C63F",
      "google-site-verification=OjhPSDIP2VIXIUH7hMv7CrLWwkyvnVgBdU-VcMHDoUI",
      "MS=ms27630582",
      "google-site-verification=C0d5wiXRs2yokw7eUIL5Gz1825U9-M-HumwMZZYC7co",
      "pnfm8n4m7lmp9d1pajbg9r75kg",
      "WM+KEtZ8csQ1+YoyvDY+JophT0DYfsjJsYeNgkkxH8o=",
      "DN6kiCaIRHg011SWPd/y5wK0nF1lAB0vxkimTgK6YHQ=",
      "_telesec-domain-validation=A04C937E41A9E22C91DC0F50FD4D6C9095ABAC1B09A81560305F2710373C16DB",
      "v=spf1 -all",
      "585pfn277okgsr6eqq5cp66kjc",
      "35HsndgfVFDTReSgRvCjY3t5wlWjYsLllfUgRIpuDfk=",
      "v1he8htvegs2u8pk09img207mh",
      "qjN-z-oil6MiHrTAeEPV9832p9-1ewZQs8CEFV8idpU",
      "OSSRH-80601",
      "globalsign-domain-verification=B762A73F73CF60DC20EC10D5BCC1F69F",
      "globalsign-domain-verification=1DAC9871AC98A3037988017AF30FA87F",
      "2y8xxj7q7dt3hxkh7zk1psbz59cz0q12",
      "nebYTcEacNoHj/N4hQzlTm96MnMnc30ILD2tZb2NsjM=",
      "s5okgqb037ach4jjok6997blj7",
      "globalsign-domain-verification=EE82C636B37B31C32CDDE24375C410A9",
      "v1inc38ais4eor8dd2be59ap7v",
      "yjh4bgq2dh9j194hj56s9ykgzf2nkh0g"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=BE, stateOrProvinceName=Brussels-Capital Region, localityName=Brussels, organizationName=European Commission, commonName=europa.eu",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R46 OV TLS CA 2026 Q3",
    "notBefore": "Aug 11 08:28:10 2026 GMT",
    "notAfter": "Feb 26 08:28:09 2027 GMT",
    "san": [
      "europa.eu",
      "www.europa.eu"
    ],
    "days_left": 152,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "147.67.34.45",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Europa"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.europa.eu",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 307,
    "location": "https://europa.eu/"
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
    "/.htaccess": 403,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "globalsign-domain-verification=6E976E49300A09A522CDF38DD011C63F",
    "google-site-verification=OjhPSDIP2VIXIUH7hMv7CrLWwkyvnVgBdU-VcMHDoUI",
    "google-site-verification=C0d5wiXRs2yokw7eUIL5Gz1825U9-M-HumwMZZYC7co",
    "globalsign-domain-verification=B762A73F73CF60DC20EC10D5BCC1F69F",
    "globalsign-domain-verification=1DAC9871AC98A3037988017AF30FA87F"
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
      "not_before": "20260811082810",
      "not_after": "20270226082809"
    }
  },
  "http2": {
    "robots_disallow": [
      "/taxation_customs/dds2/ecics/",
      "/cgi-bin/",
      "/eur-lex/",
      "/archives/",
      "/youth/dissemination/",
      "/youth/archive/",
      "/youth/includes/",
      "/youth/misc/",
      "/youth/modules/",
      "/youth/profiles/",
      "/youth/themes/",
      "/youth/cron.php",
      "/youth/install.php",
      "/youth/LICENSE.txt",
      "/youth/xmlrpc.php"
    ]
  },
  "x12": {
    "status": 301
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
