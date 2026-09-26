# Security Audit Report — automattic.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://automattic.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | automattic.com |
| Test date | 2026-09-25 23:12 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 2, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | CT1 | 15 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: clear
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] 15 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "automattic.com",
  "dns": {
    "a": [
      "192.0.78.25",
      "192.0.78.24"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx-dfw.automattic.com (pref 10)",
      "mx-ams.automattic.com (pref 10)"
    ],
    "ns": [
      "ns2.automattic.com.",
      "ns1.automattic.com.",
      "ns4.automattic.com.",
      "ns3.automattic.com."
    ],
    "spf": [
      "atlassian-domain-verification=HLvi8VknRfLwuOZ7TmiaKM8GgOgai45SxxeWZddVaOBMgWielcwit/LmLXXPJm6G",
      "yahoo-verification-key=8dNdxvmgAf9M2eCeh79q5CpzcsN5GkkT9db3Z5Rr3Sk=",
      "google-site-verification=F4jw0P5BvBnjqDSVJEhYv3LEU2WLuqChlBLJEYA2SO0",
      "figma-domain-verification=a2e41510ac6b0c5745595c76770385bfd602709c6d04e80ef830c9c482fc9e20-1768211767",
      "spf2.0/mfrom a mx ?all",
      "google-site-verification=l3pF3D6Nfuk18StNUFWXaEEIVTjBWWHvvZYP9sXEAcc",
      "v=spf1 include:_spf.automattic.com include:mail.zendesk.com include:mg-spf.greenhouse.io include:sendgrid.net include:39653948.spf04.hubspotemail.net ~all",
      "anthropic-domain-verification-q5pmy9=Tj43pQ6DCN1JcMx95QuvpbFG3",
      "gradle-verification=1AG8E2HVI4P8EOH4BK5URAEO6JVML"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:0bqp2jnw@ag.dmarcian.com; ruf=mailto:0bqp2jnw@fr.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=automattic.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Aug 10 19:43:59 2026 GMT",
    "notAfter": "Nov  8 19:43:58 2026 GMT",
    "san": [
      "*.automattic.com",
      "automattic.com"
    ],
    "days_left": 43,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.78.25",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "Automattic &#8211; Making the web a better place"
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
      "origin": "https://sub.automattic.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://automattic.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 15,
    "notable": [],
    "sample": [
      "automattic.com",
      "concierge.automattic.com",
      "engels.automattic.com",
      "fieldguide.automattic.com",
      "lounge.automattic.com",
      "museum.automattic.com",
      "offline.automattic.com",
      "publisherblog.automattic.com",
      "svn.automattic.com",
      "tls.automattic.com",
      "trac.automattic.com",
      "transparency.automattic.com",
      "updates.automattic.com",
      "www.automattic.com",
      "www.engels.automattic.com"
    ]
  },
  "elapsed_s": 45.4,
  "rechecked": "2026-09-25 23:12 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
