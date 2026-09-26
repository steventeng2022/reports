# Security Audit Report — dashlane.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dashlane.com/ |
| Bug bounty program | Dashlane |
| Listed scope domain | dashlane.com |
| Test date | 2026-09-26 18:49 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 2, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
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
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.26.218:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.26.218:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Header reveals: cloudflare
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
- **Detail:** Apex TXT records with verification/token content: openai-domain-verification=dv-4e55Awe1PWzWlnozKcMcHLLN; stripe-verification=F6D326204AE8297C7C1DCE7B72D865C2DF049FEF4E46AA6BACEE6316D87F; detectify-verification=19ea3dd383daec40adcb74a7968825b8
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of dashlane.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 6 disallow path(s), e.g. /payment, /, /payment, /payment, /payment
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "dashlane.com",
  "dns": {
    "a": [
      "104.18.26.218",
      "104.18.27.218"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-1381.awsdns-44.org.",
      "ns-1838.awsdns-37.co.uk.",
      "ns-396.awsdns-49.com.",
      "ns-646.awsdns-16.net."
    ],
    "spf": [
      "CKO=cli_mi3ag5v4v5ie3fcimbb5zcjkdi",
      "_yqvhaiv5owhbgbsa4qdcii7szjyce9m",
      "openai-domain-verification=dv-4e55Awe1PWzWlnozKcMcHLLN",
      "ca3-3ad4d01464cb4caaad75392931cf4b49",
      "stripe-verification=F6D326204AE8297C7C1DCE7B72D865C2DF049FEF4E46AA6BACEE6316D87F404F",
      "0ed1fe018a052438ee880c4b2fb7f1796949e855a2",
      "KOmW3ca2DpgwtUwRLQ4RHREFYMTccYEbcgnu7ipuO8syoAZI6C3u7zcGX8zAw9ssJDdffzxQinO7UJCu3PvDdA==",
      "_klajo684kaqqtg2dul51ana7m7aol1s",
      "detectify-verification=19ea3dd383daec40adcb74a7968825b8",
      "stripe-verification=237c0c2be4be590e020173f0d294be75fc3de8a6271806f084d2018b62d33372",
      "google-site-verification=6lT65mGzmxxPStSgeiblmtFtT4u5V3PJYdIJ2dFu5So",
      "anthropic-domain-verification-7k1h5w=lnSRFRHXgc8eyEwyyyEs0MZTE",
      "jamf-site-verification=i2cgTr97X6Qxa-MZy8gprA",
      "ca3-8b5b3457e553481da2ecf93bdf264443",
      "1|www.dashlane.com",
      "google-site-verification=yS6BK31Z2KXSj9dmrqfPzPshkE7b32wulJmzfiz4EUY",
      "v=spf1 include:_spf.google.com include:spf2.dashlane.com include:mail.zendesk.com include:mktomail.com include:mg-spf.greenhouse.io include:_spf.salesforce.com -all",
      "wrike-verification=MjM0Nzk4OTpkODUzOWI2ZTk1ZjgyOWUxZDE2MDBmMWIyNmUxODUwODdiMTdkYjA5MjgyNjY3YjEwNmI2NzFmNTcyZjJiZGEz",
      "drift-domain-verification=3e92a53ea6894b4f337d741ba27c2ab31c8630fc4eed6403e438a4fdfb162a02",
      "atlassian-domain-verification=RFwRELa7WvbbTQW5f6j9hPJUSLTAovvSepABK6YwHaeC6AcZtml0apL64eQFCdNQ",
      "ca3-f1f15d7cb167404ab9c514c3b87529c0",
      "MS=ms78056367",
      "google-site-verification=ozFOOl99Gxv4y-55zHWOduavfcmZEXqS1yR_CDVmupI",
      "miro-verification=36887a2acef64995e895317181e786f8fbc6ce21"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=r; rua=mailto:dmarc-reports@dashlane.com; ruf=mailto:dmarc-reports@dashlane.com; rf=afrf; pct=100; ri=86400"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=dashlane.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 23 18:43:28 2026 GMT",
    "notAfter": "Dec 22 19:43:05 2026 GMT",
    "san": [
      "dashlane.com",
      "check.dashlane.com",
      "*.check.dashlane.com"
    ],
    "days_left": 87,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.26.218",
    "open": [
      8080,
      8443
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
  "cookies": [
    {
      "domain": "dashlane.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.dashlane.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://dashlane.com/"
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
    "openai-domain-verification=dv-4e55Awe1PWzWlnozKcMcHLLN",
    "stripe-verification=F6D326204AE8297C7C1DCE7B72D865C2DF049FEF4E46AA6BACEE6316D87F",
    "detectify-verification=19ea3dd383daec40adcb74a7968825b8",
    "stripe-verification=237c0c2be4be590e020173f0d294be75fc3de8a6271806f084d2018b62d3",
    "google-site-verification=6lT65mGzmxxPStSgeiblmtFtT4u5V3PJYdIJ2dFu5So"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260923184328",
      "not_after": "20261222194305"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/payment",
      "/",
      "/payment",
      "/payment",
      "/payment",
      "/payment"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 4.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
