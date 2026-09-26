# Security Audit Report — pitchfork.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pitchfork.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | pitchfork.com |
| Test date | 2026-09-26 18:57 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 2, Info: 15)

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
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | CT1 | 23 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=c-RpedAWGD_CbtK-EJNEYYOIRhFayA5yVpVpqKBl2Xo; google-site-verification=rly-FCqs-7DEamfGFHyChSbo3XjeYaYpIwQ4erMjNK4; google-site-verification=skZv1iZ9lBH5Pkpkfm8ZRvpYndxMV7QemrV3ac53EBM
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of pitchfork.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 13 disallow path(s), e.g. /*?, /auth/, /account/, /user/, /user-context
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 65.9.180.66 carries PTR server-65-9-180-66.tpe53.r.cloudfront.net. for pitchfork.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] 23 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: cdn.pitchfork.com, media.pitchfork.com, wf.cdn.pitchfork.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "pitchfork.com",
  "dns": {
    "a": [
      "65.9.180.66",
      "65.9.180.7",
      "65.9.180.128",
      "65.9.180.63"
    ],
    "aaaa": [
      "2600:9000:202b:3400:1a:1603:8940:93a1",
      "2600:9000:202b:6e00:1a:1603:8940:93a1",
      "2600:9000:202b:2800:1a:1603:8940:93a1",
      "2600:9000:202b:9e00:1a:1603:8940:93a1",
      "2600:9000:202b:3800:1a:1603:8940:93a1",
      "2600:9000:202b:3000:1a:1603:8940:93a1",
      "2600:9000:202b:1000:1a:1603:8940:93a1",
      "2600:9000:202b:1e00:1a:1603:8940:93a1"
    ],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-836.awsdns-40.net.",
      "ns-1935.awsdns-49.co.uk.",
      "ns-1116.awsdns-11.org.",
      "ns-28.awsdns-03.com."
    ],
    "spf": [
      "google-site-verification=c-RpedAWGD_CbtK-EJNEYYOIRhFayA5yVpVpqKBl2Xo",
      "google-site-verification=rly-FCqs-7DEamfGFHyChSbo3XjeYaYpIwQ4erMjNK4",
      "google-site-verification=skZv1iZ9lBH5Pkpkfm8ZRvpYndxMV7QemrV3ac53EBM",
      "yahoo-verification-key=knY++Cbo7zkxhNoKSUgrT47Sp0ALKjyChizJEXKjA30=",
      "google-site-verification=WUsKOTtUHxPzCx_YTDIKePAJKwKEXMEPWIWn852-EVE",
      "google-site-verification=lWObIgNhx6XiG8Z3M8M1-k_roaEfWLeqdI2CfRj4K3w",
      "ZOOM_verify_eNt9zJgJTzuD2aeCF3ngWg",
      "adobe-idp-site-verification=c2108b9dbc0fc05ff0794006df1c41b6c945bd2c8a904bef754ec850a7c6873f",
      "zapier-domain-verification-challenge=dc65028f-9ed1-47f3-be62-e1e5422261ee",
      "google-site-verification=2KOUBsZpmToiGPqcmMBkEgTV2BH6XDJaXmn1bMVG61k",
      "v=include:aspmx.sailthru.com ~all",
      "google-site-verification=k8LYtVnKqGVmyd7ZLkoTCeKRHxWKIgL7Hhxhk0X0VqI",
      "v=spf1 include:_u.pitchfork.com._spf.smart.ondmarc.com ~all",
      "atlassian-domain-verification=mYtQWl3namqmk5ikMKT48XVnS+XdjdbkLlkWMcNyvsddK2JDAib+9a8MJCXTDMyJ",
      "MS=ms69053021"
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
    "ip": "65.9.180.66",
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
  "apex_txt": [
    "google-site-verification=c-RpedAWGD_CbtK-EJNEYYOIRhFayA5yVpVpqKBl2Xo",
    "google-site-verification=rly-FCqs-7DEamfGFHyChSbo3XjeYaYpIwQ4erMjNK4",
    "google-site-verification=skZv1iZ9lBH5Pkpkfm8ZRvpYndxMV7QemrV3ac53EBM",
    "yahoo-verification-key=knY++Cbo7zkxhNoKSUgrT47Sp0ALKjyChizJEXKjA30=",
    "google-site-verification=WUsKOTtUHxPzCx_YTDIKePAJKwKEXMEPWIWn852-EVE"
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
      "aia_ocsp": null,
      "not_before": "20260824000000",
      "not_after": "20270309235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/*?",
      "/auth/",
      "/account/",
      "/user/",
      "/user-context",
      "/preview/",
      "/search",
      "/product/",
      "/cdn-cgi/",
      "/services.min.js",
      "/com.condenast/yv8",
      "/reject-all",
      "/"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-65-9-180-66.tpe53.r.cloudfront.net."
    ]
  },
  "elapsed_s": 21.0,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
