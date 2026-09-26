# Security Audit Report — justgiving.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://justgiving.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | justgiving.com |
| Test date | 2026-09-26 01:46 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | CT1 | 38 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 8. [INFO] 38 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: app.justgiving.com, blog.justgiving.com, csp-report.staging.justgiving.com, fitness.staging.justgiving.com, graphql.staging.justgiving.com, help.justgiving.com, id.staging.justgiving.com, internal.staging.justgiving.com, media.justgiving.com, pagesettings.staging.justgiving.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "justgiving.com",
  "dns": {
    "a": [
      "3.169.55.116",
      "3.169.55.28",
      "3.169.55.52",
      "3.169.55.71"
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
      "docker-verification=eb8aed88-9460-4fab-9ef2-5ce59854ecc7",
      "00D200000000iaP=1TBN2000000015l",
      "smartsheet-site-validation=-ukamuNj8Xn3s0SyCGx2Xe5Vt2oDQ46I",
      "google-site-verification=9Ie7V9M2YudzHmywa873FdLnRJKZY57zwKHzQLgj_Kw",
      "0TPSldHHJ3AnIIANqD3HTiUcd/40SZ097zvG7L1hCQsTA5IkkNpnVNZhBPjaoZJjwCPHtr8iDe8kdsvHGi9xSA==",
      "miro-verification=0a2e1dbb2412c140c5fd914272eb7e9480bf1d6e",
      "CKO=cli_nsgsiliz6ygezevfc2osdkvtju",
      "MS=ms30587875",
      "MS=ms21109735",
      "google-site-verification=a4kUdVdhuRGENeMFXISY5ile-NsMNYxcyAsHknjaeSs",
      "figma-domain-verification=8a13494f101d6ca661f43b722f9d090d5a2a2ac65283628d50cfea15ce7e3076-1723691631",
      "google-site-verification=2l0z9VQCacbAFBgCmfbC47bnTeHQcq4LWOHoIzYG72Q",
      "lucid-verification=fcj@cjz6eat.zgj9WMQ",
      "atlassian-domain-verification=S8uXCQd2FYeOlTqNnRo41gCwYfu8sO1gASeWx63dP5j6Yh0iNdqHotTlne8l2f50",
      "mixpanel-domain-verify=5386caff-2971-4e94-aee0-4d3b5ab42b90",
      "MS=ms82130383",
      "MS=ms63724168",
      "CKO=cli_r5yskqycwsle3mrla2l4xig4pa",
      "_ziryvqp598rhu877n5y4wj0shxxojdp",
      "adobe-sign-verification=e1e4662cb4cb8921b04ff65aacba0578",
      "anthropic-domain-verification-bkk0a0=vsXwOsqFiYmbQeQS4m4KiVc0Y",
      "v=spf1 mx a include:cust-spf.exacttarget.com include:mktomail.com include:spf.protection.outlook.com include:mail.zendesk.com include:spf.mandrillapp.com -all",
      "stripe-verification=3c386b3bd938d27ee26d142e2d3201f0d49dfd68edc01090aeb71a5d542819aa"
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
    "ip": "3.169.55.116",
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
  "elapsed_s": 10.9,
  "rechecked": "2026-09-26 04:00 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
