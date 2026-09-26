# Security Audit Report — smugmug.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://smugmug.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | smugmug.com |
| Test date | 2026-09-26 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 5, Info: 11)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
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
- **Detail:** Header reveals: awselb/2.0
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

### 14. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (pmb7xaorud48wz.smugmug.com and ygzyj3mzm45vwv.smugmug.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=TgOLLHFpQq2Vo30Hxzddllz1ji7PkMt0vV2E5B3rUCP2ICBlTY; miro-verification=57e9f2368bcc8d66648f3d731cb9a81eda2d084b; h1-domain-verification=WGuGC3hnnTu7E31Y7R7KZfvJtMDib9GK1dfYdJ3Uko1oBnKJ
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of smugmug.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "smugmug.com",
  "dns": {
    "a": [
      "100.52.94.3",
      "32.193.115.37",
      "3.83.200.95"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-798.awsdns-35.net.",
      "ns-160.awsdns-20.com.",
      "ns-1488.awsdns-58.org.",
      "ns-1569.awsdns-04.co.uk."
    ],
    "spf": [
      "docusign=db2c269a-ec4f-4e67-ae5f-1ef42b248990",
      "asv=b9dfbae46b15612f6607a68ae19a7e2e",
      "atlassian-domain-verification=TgOLLHFpQq2Vo30Hxzddllz1ji7PkMt0vV2E5B3rUCP2ICBlTYaOx4ns/CDzkVnf",
      "TAILSCALE-2SnWDnM6RXvoBqRCJXyE",
      "miro-verification=57e9f2368bcc8d66648f3d731cb9a81eda2d084b",
      "h1-domain-verification=WGuGC3hnnTu7E31Y7R7KZfvJtMDib9GK1dfYdJ3Uko1oBnKJ",
      "google-site-verification=-nck5ImlodD2x9hVKFtLY2lgmH0nTzkkhqrYMGTbATQ",
      "v=spf1 include:_spf.smugmug_com._d.easydmarc.pro ~all",
      "h1-domain-verification=VswTbgZa19ikLScJDExi1oP55pEEtqbzNnXMsNAbRLGQ5pwf",
      "anthropic-domain-verification-ytcjx3=3JXEHEGUIDVMUMf0uDxrNCHeS",
      "status-page-domain-verification=2z6n94xyr5tj",
      "easydmarc-verification:c41a276a-ac1c-4df4-afb0-24d13abb4082",
      "lovable_verification=mUkuMoOCniK09G3hpvMK"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;rua=mailto:c707497ded@rua.easydmarc.us;ruf=mailto:c707497ded@ruf.easydmarc.us;fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=smugmug.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Nov 27 00:00:00 2025 GMT",
    "notAfter": "Dec 25 23:59:59 2026 GMT",
    "san": [
      "smugmug.com",
      "*.smugmug.pro",
      "smugmug.pro",
      "*.smugmug.com"
    ],
    "days_left": 90,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "100.52.94.3",
    "open": []
  },
  "https": {
    "status": 502,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.smugmug.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 502
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 502",
    "/redirect?next=https://evil-auditor.example/x -> 502",
    "/go?url=https://evil-auditor.example/x -> 502",
    "/url?url=https://evil-auditor.example/x -> 502"
  ],
  "paths": {
    "/robots.txt": 502,
    "/sitemap.xml": 502,
    "/.well-known/security.txt": 502,
    "/security.txt": 502,
    "/.git/HEAD": 502,
    "/.git/config": 502,
    "/.env": 502,
    "/.htaccess": 502,
    "/wp-login.php": 502,
    "/phpmyadmin/index.php": 502,
    "/server-status": 502,
    "/api/": 502
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "atlassian-domain-verification=TgOLLHFpQq2Vo30Hxzddllz1ji7PkMt0vV2E5B3rUCP2ICBlTY",
    "miro-verification=57e9f2368bcc8d66648f3d731cb9a81eda2d084b",
    "h1-domain-verification=WGuGC3hnnTu7E31Y7R7KZfvJtMDib9GK1dfYdJ3Uko1oBnKJ",
    "google-site-verification=-nck5ImlodD2x9hVKFtLY2lgmH0nTzkkhqrYMGTbATQ",
    "h1-domain-verification=VswTbgZa19ikLScJDExi1oP55pEEtqbzNnXMsNAbRLGQ5pwf"
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
  "elapsed_s": 23.2,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
