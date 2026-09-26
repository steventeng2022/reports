# Security Audit Report — nasa.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nasa.gov/ |
| Bug bounty program | Nasa VDP |
| Listed scope domain | nasa.gov |
| Test date | 2026-09-25 10:03 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "nasa.gov",
  "dns": {
    "a": [
      "192.0.66.108"
    ],
    "aaaa": [
      "2a04:fa87:fffd::c000:426c"
    ],
    "cname": null,
    "mx": [
      "nasa-gov.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "a5-66.akam.net.",
      "a9-64.akam.net.",
      "a14-67.akam.net.",
      "a8-66.akam.net.",
      "a1-32.akam.net.",
      "a12-64.akam.net."
    ],
    "spf": [
      "pvv8mevb6qrmqvqi8alhmreg42",
      "1HqDXPHdt8JOt02qy6FB+l3+Z1zXScqcPxlE/faXjZLS9FRbVhHCUCHQE2bWofZt2TWKPchjjma3Pqli4FULFw==",
      "google-site-verification=BUxd0xTJY4ZjGohBwKDpNms-yOATz92Y54kgme4eKHs",
      "MS=ms93625004",
      "nmh1f9tgxhmfmjkshg7qh595drdfgnf1",
      "smartsheet-site-validation=gnL11HAQqHlH1tQabmxKf12b5ZCNxJfx",
      "v=spf1 include:_spf-4a.nasa.gov include:_spf-4b.nasa.gov include:_spf-4c.nasa.gov include:_spf-4d.nasa.gov include:_spf-4g.nasa.gov include:_spf-4m.nasa.gov include:_spf-4x.nasa.gov include:_spf-6a.nasa.gov include:spf.protection.outlook.com -all",
      "atlassian-sending-domain-verification=4730ddf4-d24e-4a91-9612-cb14998d0e47",
      "openai-domain-verification=dv-CO0ENDLO7EB9V5E4JnmE6pS8",
      "webexdomainverification.1YPST=f98a61ea-b92e-41f2-87aa-5651b2af43b8",
      "amazonses:PvUL7T41LO87xjr+2nfgxTu11i75NeT9HzY3xYv82Ko=",
      "mj8729pr7k44dx62wwtx5745xr5njzkn",
      "docusign=4025560e-93c9-4920-bb13-849c6fc35d58",
      "amazonses:FXFVeQnEO3Wua+aY/H4aOIH3sSwteE+7YpGrwm8kF/s=",
      "atlassian-domain-verification=oNzRM7G9GIAL/LLP5c7sPOQiAHsHrQ1hKcU7GGZ0ADRZJFhUB/upe935/2RYq/jO",
      "HRlHXyx8jXo+9pIaJWFVBPOLVfeI2biAj3VT1woaTFpp05D5/q6AoD5KpUgws539/d2jl8wBJiEr58OEsRVugQ==",
      "uechcfoubh169akghg2214p54n",
      "n39n7frbwnkhcmky2nps779y4ttn61wl",
      "asv=12d88629ae88f5017642bfc4981f8dd7",
      "apple-domain-verification=qw51K0kGzRHLbN9S",
      "openai-domain-verification=dv-Fbq5PVntP9qLelQPUBKniDjr",
      "google-site-verification=ZKpcXLqaBX3jND8Fybkvr3MaaOpC_6MRjXBYm0XNkJQ"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarcmail@mail.nasa.gov,mailto:reports@dmarc.cyber.dhs.gov"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=nasa.gov",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Aug 11 23:22:59 2026 GMT",
    "notAfter": "Nov  9 23:22:58 2026 GMT",
    "san": [
      "nasa.gov",
      "www.nasa.gov"
    ],
    "days_left": 45,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.66.108",
    "open": []
  },
  "https": {
    "status": 302,
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
      "origin": "https://sub.nasa.gov",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://nasa.gov/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 46.1,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
