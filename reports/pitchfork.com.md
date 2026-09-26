# Security Audit Report — pitchfork.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pitchfork.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | pitchfork.com |
| Test date | 2026-09-26 01:46 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 2, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | CT1 | 23 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] 23 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: cdn.pitchfork.com, media.pitchfork.com, wf.cdn.pitchfork.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "pitchfork.com",
  "dns": {
    "a": [
      "65.9.180.63",
      "65.9.180.128",
      "65.9.180.7",
      "65.9.180.66"
    ],
    "aaaa": [
      "2600:9000:202b:c00:1a:1603:8940:93a1",
      "2600:9000:202b:ea00:1a:1603:8940:93a1",
      "2600:9000:202b:c800:1a:1603:8940:93a1",
      "2600:9000:202b:6a00:1a:1603:8940:93a1",
      "2600:9000:202b:9400:1a:1603:8940:93a1",
      "2600:9000:202b:cc00:1a:1603:8940:93a1",
      "2600:9000:202b:e000:1a:1603:8940:93a1",
      "2600:9000:202b:8c00:1a:1603:8940:93a1"
    ],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-28.awsdns-03.com.",
      "ns-1116.awsdns-11.org.",
      "ns-836.awsdns-40.net.",
      "ns-1935.awsdns-49.co.uk."
    ],
    "spf": [
      "google-site-verification=k8LYtVnKqGVmyd7ZLkoTCeKRHxWKIgL7Hhxhk0X0VqI",
      "yahoo-verification-key=knY++Cbo7zkxhNoKSUgrT47Sp0ALKjyChizJEXKjA30=",
      "v=include:aspmx.sailthru.com ~all",
      "ZOOM_verify_eNt9zJgJTzuD2aeCF3ngWg",
      "google-site-verification=lWObIgNhx6XiG8Z3M8M1-k_roaEfWLeqdI2CfRj4K3w",
      "zapier-domain-verification-challenge=dc65028f-9ed1-47f3-be62-e1e5422261ee",
      "atlassian-domain-verification=mYtQWl3namqmk5ikMKT48XVnS+XdjdbkLlkWMcNyvsddK2JDAib+9a8MJCXTDMyJ",
      "adobe-idp-site-verification=c2108b9dbc0fc05ff0794006df1c41b6c945bd2c8a904bef754ec850a7c6873f",
      "MS=ms69053021",
      "google-site-verification=c-RpedAWGD_CbtK-EJNEYYOIRhFayA5yVpVpqKBl2Xo",
      "google-site-verification=WUsKOTtUHxPzCx_YTDIKePAJKwKEXMEPWIWn852-EVE",
      "v=spf1 include:_u.pitchfork.com._spf.smart.ondmarc.com ~all",
      "google-site-verification=skZv1iZ9lBH5Pkpkfm8ZRvpYndxMV7QemrV3ac53EBM",
      "google-site-verification=2KOUBsZpmToiGPqcmMBkEgTV2BH6XDJaXmn1bMVG61k",
      "google-site-verification=rly-FCqs-7DEamfGFHyChSbo3XjeYaYpIwQ4erMjNK4"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; sp=reject; rua=mailto:a6816915@inbox.ondmarc.com; ruf=mailto:a6816915@inbox.ondmarc.com; adkim=r; aspf=r; fo=1; rf=afrf; ri=3600"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=pitchfork.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Aug 24 00:00:00 2026 GMT",
    "notAfter": "Mar  9 23:59:59 2027 GMT",
    "san": [
      "pitchfork.com",
      "*.pitchfork.com"
    ],
    "days_left": 164,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "65.9.180.63",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Pitchfork | The Most Trusted Voice in Music. | Pitchfork"
  },
  "mixed_content": [
    "href=\"http://",
    "href=\"http://",
    "href=\"http://"
  ],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [
    {
      "domain": ".pitchfork.com"
    },
    {
      "domain": ".pitchfork.com"
    },
    {
      "domain": ".pitchfork.com",
      "samesite": "none"
    },
    {
      "domain": ".pitchfork.com",
      "samesite": "none"
    },
    {
      "domain": ".pitchfork.com",
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
      "origin": "https://sub.pitchfork.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://pitchfork.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 23,
    "notable": [
      "cdn.pitchfork.com",
      "media.pitchfork.com",
      "wf.cdn.pitchfork.com"
    ],
    "sample": [
      "c.pitchfork.com",
      "c2.pitchfork.com",
      "cdn.pitchfork.com",
      "cdn2.pitchfork.com",
      "cdn3.pitchfork.com",
      "cdn4.pitchfork.com",
      "forktracks.pitchfork.com",
      "interactive-stag.pitchfork.com",
      "interactive.pitchfork.com",
      "link.pitchfork.com",
      "links.pitchfork.com",
      "media.pitchfork.com",
      "merch.pitchfork.com",
      "permutive.pitchfork.com",
      "pitchfork.com",
      "qc.pitchfork.com",
      "readerspoll.pitchfork.com",
      "sstats.pitchfork.com",
      "stag-forktracks.pitchfork.com",
      "stag-media.pitchfork.com"
    ]
  },
  "elapsed_s": 27.9,
  "rechecked": "2026-09-26 04:00 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
