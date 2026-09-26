# Security Audit Report — justgiving.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://justgiving.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | justgiving.com |
| Test date | 2026-09-26 17:48 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 1, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | MAIL10 | DMARC subdomain policy (sp=) set while apex policy is p=none | CWE-285 |
| 9 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 10 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 11 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 12 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | info | CT1 | 38 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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
- **Detail:** Detected: Server: AmazonS3
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AmazonS3
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] DMARC subdomain policy (sp=) set while apex policy is p=none (`MAIL10`)

- **CWE:** CWE-285
- **Detail:** Subdomains are enforced while the apex domain is monitor-only.
- **Recommendation:** Confirm the split policy is intended.

### 9. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 10. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 11. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: adobe-sign-verification=e1e4662cb4cb8921b04ff65aacba0578; lucid-verification=fcj@cjz6eat.zgj9WMQ; figma-domain-verification=8a13494f101d6ca661f43b722f9d090d5a2a2ac65283628d50cfea
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 12. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of justgiving.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 37 disallow path(s), e.g. /, /, /user-account/, /charity/search, /fundraiser/search
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [INFO] 38 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: app.justgiving.com, blog.justgiving.com, csp-report.staging.justgiving.com, fitness.staging.justgiving.com, graphql.staging.justgiving.com, help.justgiving.com, id.staging.justgiving.com, internal.staging.justgiving.com, media.justgiving.com, pagesettings.staging.justgiving.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "justgiving.com",
  "dns": {
    "a": [
      "3.169.55.28",
      "3.169.55.116",
      "3.169.55.71",
      "3.169.55.52"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx2.blackbaud.iphmx.com (pref 5)",
      "mx1.blackbaud.iphmx.com (pref 1)"
    ],
    "ns": [
      "ns-1865.awsdns-41.co.uk.",
      "ns-493.awsdns-61.com.",
      "ns-959.awsdns-55.net.",
      "ns-1506.awsdns-60.org."
    ],
    "spf": [
      "_ziryvqp598rhu877n5y4wj0shxxojdp",
      "CKO=cli_nsgsiliz6ygezevfc2osdkvtju",
      "adobe-sign-verification=e1e4662cb4cb8921b04ff65aacba0578",
      "MS=ms30587875",
      "lucid-verification=fcj@cjz6eat.zgj9WMQ",
      "mixpanel-domain-verify=5386caff-2971-4e94-aee0-4d3b5ab42b90",
      "MS=ms63724168",
      "figma-domain-verification=8a13494f101d6ca661f43b722f9d090d5a2a2ac65283628d50cfea15ce7e3076-1723691631",
      "stripe-verification=3c386b3bd938d27ee26d142e2d3201f0d49dfd68edc01090aeb71a5d542819aa",
      "google-site-verification=a4kUdVdhuRGENeMFXISY5ile-NsMNYxcyAsHknjaeSs",
      "google-site-verification=2l0z9VQCacbAFBgCmfbC47bnTeHQcq4LWOHoIzYG72Q",
      "smartsheet-site-validation=-ukamuNj8Xn3s0SyCGx2Xe5Vt2oDQ46I",
      "atlassian-domain-verification=S8uXCQd2FYeOlTqNnRo41gCwYfu8sO1gASeWx63dP5j6Yh0iNdqHotTlne8l2f50",
      "miro-verification=0a2e1dbb2412c140c5fd914272eb7e9480bf1d6e",
      "00D200000000iaP=1TBN2000000015l",
      "0TPSldHHJ3AnIIANqD3HTiUcd/40SZ097zvG7L1hCQsTA5IkkNpnVNZhBPjaoZJjwCPHtr8iDe8kdsvHGi9xSA==",
      "MS=ms82130383",
      "anthropic-domain-verification-bkk0a0=vsXwOsqFiYmbQeQS4m4KiVc0Y",
      "google-site-verification=9Ie7V9M2YudzHmywa873FdLnRJKZY57zwKHzQLgj_Kw",
      "MS=ms21109735",
      "CKO=cli_r5yskqycwsle3mrla2l4xig4pa",
      "docker-verification=eb8aed88-9460-4fab-9ef2-5ce59854ecc7",
      "v=spf1 mx a include:cust-spf.exacttarget.com include:mktomail.com include:spf.protection.outlook.com include:mail.zendesk.com include:spf.mandrillapp.com -all"
    ],
    "dmarc": [
      "v=DMARC1; p=none; pct=100; rua=mailto:re+gbzuz3j7wtb@dmarc.postmarkapp.com,mailto:re+or5o1vetcy9@dmarc.postmarkapp.com; sp=none; aspf=r;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.justgiving.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Nov  3 00:00:00 2025 GMT",
    "notAfter": "Dec  1 23:59:59 2026 GMT",
    "san": [
      "*.justgiving.com",
      "justgiving.com"
    ],
    "days_left": 66,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.55.28",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Online fundraising donations and ideas - JustGiving"
  },
  "mixed_content": [],
  "tech": [
    "Server: AmazonS3"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.justgiving.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://justgiving.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "source": "certspotter",
    "count": 38,
    "notable": [
      "app.justgiving.com",
      "blog.justgiving.com",
      "csp-report.staging.justgiving.com",
      "fitness.staging.justgiving.com",
      "graphql.staging.justgiving.com",
      "help.justgiving.com",
      "id.staging.justgiving.com",
      "internal.staging.justgiving.com",
      "media.justgiving.com",
      "pagesettings.staging.justgiving.com",
      "receipts.staging.justgiving.com",
      "staging.justgiving.com",
      "static.justgiving.com",
      "static.staging.justgiving.com",
      "tags-fitness.staging.justgiving.com"
    ],
    "sample": [
      "app.justgiving.com",
      "bbid.justgiving.com",
      "blog.justgiving.com",
      "click.contact.justgiving.com",
      "csp-report.justgiving.com",
      "csp-report.staging.justgiving.com",
      "developer.justgiving.com",
      "fitness.justgiving.com",
      "fitness.staging.justgiving.com",
      "graphql.justgiving.com",
      "graphql.staging.justgiving.com",
      "help.justgiving.com",
      "id.justgiving.com",
      "id.staging.justgiving.com",
      "image.contact.justgiving.com",
      "info.justgiving.com",
      "internal.staging.justgiving.com",
      "justgiving.com",
      "media.justgiving.com",
      "mi.justgiving.com"
    ]
  },
  "apex_txt": [
    "adobe-sign-verification=e1e4662cb4cb8921b04ff65aacba0578",
    "lucid-verification=fcj@cjz6eat.zgj9WMQ",
    "figma-domain-verification=8a13494f101d6ca661f43b722f9d090d5a2a2ac65283628d50cfea",
    "stripe-verification=3c386b3bd938d27ee26d142e2d3201f0d49dfd68edc01090aeb71a5d5428",
    "google-site-verification=a4kUdVdhuRGENeMFXISY5ile-NsMNYxcyAsHknjaeSs"
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
    "hsts_preloaded": true,
    "robots_disallow": [
      "/",
      "/",
      "/user-account/",
      "/charity/search",
      "/fundraiser/search",
      "/charities/beta/account/login",
      "/share-success/",
      "/user-account/",
      "/charity/search",
      "/fundraiser/search",
      "/charities/beta/account/login",
      "/share-success/",
      "/user-account/",
      "/charity/search",
      "/fundraiser/search"
    ]
  },
  "elapsed_s": 12.2,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
