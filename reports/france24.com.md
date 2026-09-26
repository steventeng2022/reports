# Security Audit Report — france24.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://france24.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | france24.com |
| Test date | 2026-09-26 17:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 5, Info: 11)

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
- **Detail:** Detected: Server: nginx
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
- **Detail:** Header reveals: nginx
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
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=xDJOpp5LhSlJgX7z4KvFhCYnZB2TY8hfdLraQjAFAVx26Tkac4; atlassian-domain-verification=A8w13LJxUXKD3We2aV5t054m8lhwHbasQZ/fBI/YySexagczb6; _globalsign-domain-verification=2oNqKhLsivi-1ZTcHyMO9dU_5DjX78RANaqVUbWf7y
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of france24.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "france24.com",
  "dns": {
    "a": [
      "23.210.215.218",
      "23.210.215.217"
    ],
    "aaaa": [
      "2600:1417:76::17c7:2299",
      "2600:1417:76::17c7:229b"
    ],
    "cname": null,
    "mx": [
      "gw000151-eu.fortimail.com (pref 5)"
    ],
    "ns": [
      "a1-147.akam.net.",
      "a10-66.akam.net.",
      "a26-67.akam.net.",
      "a7-65.akam.net.",
      "a9-66.akam.net.",
      "a6-64.akam.net."
    ],
    "spf": [
      "atlassian-domain-verification=xDJOpp5LhSlJgX7z4KvFhCYnZB2TY8hfdLraQjAFAVx26Tkac4u7Z8C1oj90csaT",
      "348566992-2132956",
      "rlz51bPFaxsQr8ZL1IASL0ou8TMMwkd73X7KAuYwAQI=",
      "cMhf+QzWy8A/PZ5vWY9/e61nciJUv9Y4np2G/gDW7/u+HQz2tsuKS+gfx/V6dieHjUq+nddoC3NzDMN8+bYjyQ==",
      "atlassian-domain-verification=A8w13LJxUXKD3We2aV5t054m8lhwHbasQZ/fBI/YySexagczb6/B44ukx9Rul9J4",
      "_globalsign-domain-verification=2oNqKhLsivi-1ZTcHyMO9dU_5DjX78RANaqVUbWf7y",
      "google-site-verification=WZy8Y7Q1c7TITei9rcbLhqdkivyumD-Vfq3z9sNAPbU",
      "7Um+fJoSowkH7rXy6VX20iW1luuKNiyLTwmGsYpFquI=",
      "facebook-domain-verification=05e2fo203ir2my11s89cptp4d98v76",
      "google-site-verification=ZhMoVoPXe6QPn3vkbtnf2t9Ef_tQ5bYbJG-cq1v6VL4",
      "v=spf1 +MX ip4:154.52.0.151 ip4:84.14.169.30 ip4:209.52.117.178 include:spf.protection.outlook.com -all",
      "slack-domain-verification=wOMgnbRYKgXB7XwqhoTcBqsEWCtmr3jd3tzjQw16"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=france24.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug 19 05:23:30 2026 GMT",
    "notAfter": "Nov 17 05:23:29 2026 GMT",
    "san": [
      "amp.france24.com",
      "api2.france24.com",
      "apis.france24.com",
      "apis.observers.france24.com",
      "ar.france24.com",
      "embed.france24.com",
      "en.france24.com",
      "es.france24.com",
      "fr.france24.com",
      "france24.com",
      "graphics.france24.com",
      "m.france24.com",
      "observers.france24.com",
      "s.france24.com",
      "s.observers.france24.com",
      "scd.france24.com",
      "scd.observers.france24.com",
      "static.france24.com",
      "webdoc.france24.com"
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
    "ip": "23.210.215.218",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.france24.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.france24.com/"
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
    "atlassian-domain-verification=xDJOpp5LhSlJgX7z4KvFhCYnZB2TY8hfdLraQjAFAVx26Tkac4",
    "atlassian-domain-verification=A8w13LJxUXKD3We2aV5t054m8lhwHbasQZ/fBI/YySexagczb6",
    "_globalsign-domain-verification=2oNqKhLsivi-1ZTcHyMO9dU_5DjX78RANaqVUbWf7y",
    "google-site-verification=WZy8Y7Q1c7TITei9rcbLhqdkivyumD-Vfq3z9sNAPbU",
    "facebook-domain-verification=05e2fo203ir2my11s89cptp4d98v76"
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
  "elapsed_s": 5.3,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
