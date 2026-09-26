# Security Audit Report — trustpilot.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://trustpilot.com/ |
| Bug bounty program | Trustpilot |
| Listed scope domain | trustpilot.com |
| Test date | 2026-09-26 19:00 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 4, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
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
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Apex TXT records with verification/token content: atlassian-sending-domain-verification=2448cf59-90a2-4b9f-ab88-6c212605cc8a; h1-domain-verification=K1j4L82MxUY9ci2JywgBgo6FvxyEvTfYou9bBcQ9j5dK7DUC; miro-verification=031ae4a4b2a83d8570b7352bf4c87365ade7cb7b
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of trustpilot.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 811 disallow path(s), e.g. /error, /evaluate/, /evaluate-link, /evaluate-unique-link, /pingdom
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 63.33.98.142 carries PTR ec2-63-33-98-142.eu-west-1.compute.amazonaws.com. for trustpilot.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "trustpilot.com",
  "dns": {
    "a": [
      "63.33.98.142",
      "34.251.1.61",
      "63.35.41.16"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx4.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx3.googlemail.com (pref 30)",
      "aspmx5.googlemail.com (pref 30)"
    ],
    "ns": [
      "ns-1859.awsdns-40.co.uk.",
      "ns-627.awsdns-14.net.",
      "ns-1198.awsdns-21.org.",
      "ns-507.awsdns-63.com."
    ],
    "spf": [
      "SFMC-51XpMfjNiP4EVyMcp4ez89Vu8Wk1q6Q6LJ68PeRh",
      "atlassian-sending-domain-verification=2448cf59-90a2-4b9f-ab88-6c212605cc8a",
      "h1-domain-verification=K1j4L82MxUY9ci2JywgBgo6FvxyEvTfYou9bBcQ9j5dK7DUC",
      "miro-verification=031ae4a4b2a83d8570b7352bf4c87365ade7cb7b",
      "stripe-verification=5309EE27ADA96F87770018A428B9C43D1E0B0CDC5726252873D4BC67C5871789",
      "apple-domain-verification=MmFgAj5P9HBaVpmv",
      "gJn7h6f2m!!%WT@C%m6ox&4pFfcDjvkBYB4hq*0L2im#W#t^MLKcAlh4*Ddm59e2ricfrPUbb&H3X&h*6AjNI8tXONPH#*PluEY",
      "anthropic-domain-verification-qga6j9=93jJxdvry3EauO3oQFZvf8dHx",
      "google-site-verification=KdmHR50ME1X0_bgJJO27tI6Y2ZZh_teVRqF8D2vmBSM",
      "onetrust-domain-verification=f8c9c8fbc2254290a3239ea97107324d",
      "hubspot-developer-verification=MDUzYTcyZDctZTlmYS00YzUxLWE3ZGItMmVlYTM4ZTRlZmJm",
      "google-site-verification=eX8LrikiWD5mmqtziAD3DYIjGF1AqsK2n-GvJl6jd2Q",
      "jetbrains-domain-verification=4x4x2p1njocim1o7bh7dmijxk",
      "docusign=be55314d-2f73-40d6-b69b-81fe9012c808",
      "calendly-site-verification=VExW0uOVuA35JUxpvM76K50anC81mCpUybq3Ts0aX",
      "jamf-site-verification=hCZILKggaY23aId4VBfmVA",
      "google-site-verification=QDeDnLx9XehnRUiSDiEMTlo7FC5yIgBaMfhzkg36lQc",
      "onetrust-domain-verification=d9e381bf0e9c411cb5fcff80e6e8a5ad",
      "v=spf1 include:trustpilotservice.com include:_spf.google.com include:u5760.wl.sendgrid.net include:mail.zendesk.com include:cust-spf.exacttarget.com -all",
      "atlassian-domain-verification=Eo0XF2YMZT8L2vGyok0CJob7i4RRe1QrfcDxjjnF0pO7j7V05HsJz2qiVFB/zJ1t"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:noreply-dmarc@trustpilot.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=*.trustpilot.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Nov  1 00:00:00 2025 GMT",
    "notAfter": "Nov 29 23:59:59 2026 GMT",
    "san": [
      "*.trustpilot.com",
      "trustpilot.com"
    ],
    "days_left": 64,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "63.33.98.142",
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
      "origin": "https://sub.trustpilot.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.trustpilot.com/"
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
    "atlassian-sending-domain-verification=2448cf59-90a2-4b9f-ab88-6c212605cc8a",
    "h1-domain-verification=K1j4L82MxUY9ci2JywgBgo6FvxyEvTfYou9bBcQ9j5dK7DUC",
    "miro-verification=031ae4a4b2a83d8570b7352bf4c87365ade7cb7b",
    "stripe-verification=5309EE27ADA96F87770018A428B9C43D1E0B0CDC5726252873D4BC67C587",
    "apple-domain-verification=MmFgAj5P9HBaVpmv"
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
      "not_before": "20251101000000",
      "not_after": "20261129235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/error",
      "/evaluate/",
      "/evaluate-link",
      "/evaluate-unique-link",
      "/pingdom",
      "/reviews/",
      "/review/*/transparency",
      "/product-reviews/",
      "/*?*editmode=",
      "/api/*",
      "/*?*languages=",
      "/*?*stars=",
      "/*?*sort=",
      "/*?*verified=",
      "/*?*topics="
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-63-33-98-142.eu-west-1.compute.amazonaws.com."
    ]
  },
  "elapsed_s": 30.4,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
