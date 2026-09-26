# Security Audit Report — eepurl.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://eepurl.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | eepurl.com |
| Test date | 2026-09-26 17:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 5, Info: 9)

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
| 12 | low | MAIL9 | DMARC enforces (p=reject) but has no reporting address (rua) | CWE-285 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

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

### 12. [LOW] DMARC enforces (p=reject) but has no reporting address (rua) (`MAIL9`)

- **CWE:** CWE-285
- **Detail:** Without a rua= reporting address the policy cannot be tuned; mis-sends may be silently quarantined.
- **Recommendation:** Add a rua= reporting mailbox to the DMARC record.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: spycloud-domain-verification=2127e2b7-da8a-44df-95f5-c77882a949b1
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of eepurl.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "eepurl.com",
  "dns": {
    "a": [
      "23.50.227.124"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [],
    "ns": [
      "a4-65.akam.net.",
      "a6-66.akam.net.",
      "a1-205.akam.net.",
      "a7-66.akam.net.",
      "a5-65.akam.net.",
      "a14-66.akam.net."
    ],
    "spf": [
      "95hl48p0xjbqydr7xyzz8ptmksl1334w",
      "524t8ygzcd8l07x0v7bhq882qj55dgsw",
      "_72ru7fr8c0ncfmjg71hyedfisw40m4h",
      "_z0wc6vmvjbvcm5fp3gts295gq1nqf8d",
      "_8hkh7i00e0luex039dp6fsfjhs4bk8u",
      "_lgool0gg7wzos9kz40nbb40e86izja0",
      "spycloud-domain-verification=2127e2b7-da8a-44df-95f5-c77882a949b1"
    ],
    "dmarc": [
      "v=DMARC1; p=reject;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Diego, organizationName=Intuit Inc., commonName=wildcardsan2.mailchimp.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Apr 16 00:00:00 2026 GMT",
    "notAfter": "Oct 31 23:59:59 2026 GMT",
    "san": [
      "wildcardsan2.mailchimp.com",
      "*.admin.mailchimp.com",
      "*.api.mailchimp.com",
      "*.campaign-archive.com",
      "*.campaign-archive1.com",
      "*.campaign-archive2.com",
      "*.chimpstatic.com",
      "*.e2e.mailchimpsites.com",
      "*.eepurl.com",
      "*.forward-to-friend.com",
      "*.forward-to-friend1.com",
      "*.forward-to-friend2.com",
      "*.list-manage.com",
      "*.list-manage1.com",
      "*.list-manage2.com",
      "*.mailchimp.com",
      "*.mailchimpsites.com",
      "*.mandrill.com",
      "*.mccrowdsource.com",
      "*.parsimony-target.mailchimp.com",
      "*.partner-api.mailchimp.com",
      "*.partners.mailchimp.com",
      "*.vip-reports.net",
      "chimpstatic.com",
      "e2e.eepurl.com",
      "eep.io",
      "eepurl.com",
      "mailchimp.com",
      "mailchimpsites.com",
      "thenomdepot.com",
      "vip-reports.net"
    ],
    "days_left": 35,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.50.227.124",
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
      "origin": "https://sub.eepurl.com",
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
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "spycloud-domain-verification=2127e2b7-da8a-44df-95f5-c77882a949b1"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null
    }
  },
  "elapsed_s": 6.4,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
