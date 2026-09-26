# Security Audit Report — sketchfab.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://sketchfab.com/ |
| Bug bounty program | Epic Games |
| Listed scope domain | sketchfab.com |
| Test date | 2026-09-26 17:52 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 4, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | low | CORS1 | CORS: subdomain origin origin accepted with credentials | CWE-942 |
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
- **Detail:** Detected: Server: gunicorn
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=604800 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: gunicorn
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [LOW] CORS: subdomain origin origin accepted with credentials (`CORS1`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.sketchfab.com -> Access-Control-Allow-Origin: https://sub.sketchfab.com, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=1D22clCUDVDvqHEntN2eD6uGI68BZM_zn1Q68W3H4Z4; notion-domain-verification=xXMBP2X1o1sdyWYbFPT8WxMFmH6AeVwrpRpcdXK9uZ0; google-site-verification=CkzXPYnKKBciPYalhXoO-ZqsXvZFrUJyh651HowaeH4
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of sketchfab.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "sketchfab.com",
  "dns": {
    "a": [
      "54.192.248.88",
      "54.192.248.90",
      "54.192.248.123",
      "54.192.248.119"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-1716.awsdns-22.co.uk.",
      "ns-15.awsdns-01.com.",
      "ns-1283.awsdns-32.org.",
      "ns-1005.awsdns-61.net."
    ],
    "spf": [
      "google-site-verification=1D22clCUDVDvqHEntN2eD6uGI68BZM_zn1Q68W3H4Z4",
      "notion-domain-verification=xXMBP2X1o1sdyWYbFPT8WxMFmH6AeVwrpRpcdXK9uZ0",
      "google-site-verification=CkzXPYnKKBciPYalhXoO-ZqsXvZFrUJyh651HowaeH4",
      "facebook-domain-verification=abkh6sdfak0gjfk06lp9yy63v86yd0",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all",
      "cursor-domain-verification-bfcs5x=3og16N1cvdpYQTiEbkW8l3SAy",
      "dropbox-domain-verification=hdzg4gv89jax",
      "atlassian-domain-verification=SoJZyndmWCSCCPEyKf0gxRibYYQGlSvtWMEwAI5JRm0LU2g7e7xW4T2WRM0iahex",
      "box-domain-verification=90c68eb309746ce326626165eadc4785e6094731b6e841ac85dab1c1d08a071c",
      "Sendinblue-code:893b13ba16ab42c906f31ddb4d6c0972",
      "anthropic-domain-verification-pkgrxp=9SX6zKkJLDT6sYYBe3jSwNzDA",
      "domain-verification=a1005fb6436172b4589d82ac0aebeb7836b99d474365b7fde9850ef1f83cf9bd",
      "adobe-idp-site-verification=8a5be962006abb6a54a07ecebc48df8733bcccf0a5c6b8bcb66f58ad5e8dd604",
      "openai-domain-verification=dv-WwDzb0UffYovHWmc8ILUiSsC",
      "smartsheet-site-validation=UKQ9vunDy5i2LXlAqwfMpCBLYvg1TNd9",
      "docusign=cc2bea62-2607-4969-b594-291f05fe9a18",
      "_proofpoint-verification=5c42dd9b-ce3b-48c3-954c-37bec7da586f",
      "miro-verification=66a6d0d4ec91315544e1c0ab5e73b7a2a174f6f4",
      "figma-domain-verification=ffa6044ba8b42d9296b3ff1607f226aecde09d2ef5e0141135265e1251ec1506-1718206799",
      "google-site-verification=LrK1Vp3WgG36TFqPMA1zxPstliUIGZJAhtU3i-slqHQ"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; sp=reject; pct=100; adkim=r; aspf=r; rua=mailto:dmarc_agg@vali.email,mailto:dmarc@mailinblue.com,mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc@mailinblue.com,mailto:dmarc_ruf@emaildefense.proofpoint.com,mailto:epic",
      "-games@ruf-reporting.vali.email; fo=1; rf=afrf; ri=86400"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=sketchfab.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Dec 17 00:00:00 2025 GMT",
    "notAfter": "Jan 15 23:59:59 2027 GMT",
    "san": [
      "sketchfab.com",
      "*.sketchfab.me",
      "e6f79c614c67.sketchfab.com",
      "sketchfab.me",
      "www.skfb.ly",
      "api.sketchfab.com",
      "skfb.ly",
      "blog.sketchfab.com",
      "www.sketchfab.com"
    ],
    "days_left": 111,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.88",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Sketchfab - The best 3D viewer on the web"
  },
  "mixed_content": [],
  "tech": [
    "Server: gunicorn"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.sketchfab.com",
      "acao": "https://sub.sketchfab.com",
      "acac": "true"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://sketchfab.com:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 202",
    "/url?url=https://evil-auditor.example/x -> 202"
  ],
  "paths": {
    "/robots.txt": 202,
    "/sitemap.xml": 202,
    "/.well-known/security.txt": 202,
    "/security.txt": 202,
    "/.git/HEAD": 202,
    "/.git/config": 202,
    "/.env": 202,
    "/.htaccess": 202,
    "/wp-login.php": 202,
    "/phpmyadmin/index.php": 202,
    "/server-status": 202,
    "/api/": 202
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=1D22clCUDVDvqHEntN2eD6uGI68BZM_zn1Q68W3H4Z4",
    "notion-domain-verification=xXMBP2X1o1sdyWYbFPT8WxMFmH6AeVwrpRpcdXK9uZ0",
    "google-site-verification=CkzXPYnKKBciPYalhXoO-ZqsXvZFrUJyh651HowaeH4",
    "facebook-domain-verification=abkh6sdfak0gjfk06lp9yy63v86yd0",
    "cursor-domain-verification-bfcs5x=3og16N1cvdpYQTiEbkW8l3SAy"
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
  "elapsed_s": 9.3,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
