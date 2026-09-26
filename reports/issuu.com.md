# Security Audit Report — issuu.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://issuu.com/ |
| Bug bounty program | Issuu |
| Listed scope domain | issuu.com |
| Test date | 2026-09-25 09:53 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 2, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=300 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

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

## Evidence (raw response observations)

```json
{
  "domain": "issuu.com",
  "dns": {
    "a": [
      "151.101.65.55",
      "151.101.1.55",
      "151.101.129.55",
      "151.101.193.55"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx.l.google.com (pref 10)",
      "aspmx2.googlemail.com (pref 40)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx3.googlemail.com (pref 50)"
    ],
    "ns": [
      "ns-1582.awsdns-05.co.uk.",
      "ns-757.awsdns-30.net.",
      "ns-1343.awsdns-39.org.",
      "ns-426.awsdns-53.com."
    ],
    "spf": [
      "google-site-verification=0H3HL1KxMhfdap89AcuCKadjU2QFxgZ0I7CXePAEReE",
      "google-site-verification=5CyB-vqN7byHfN1pa3hf-FFj_ecJbkgBJ7iJr3nso98",
      "fastly-domain-delegation-00331056-2025326",
      "google-site-verification=xh0flAgyOL5F8z5FQTMUnk4Z0nYehx9lPsDq1d2ntFY",
      "miro-verification=50d48af206c43d8ba6a5c568d0b68365b08fd197",
      "apple-domain-verification=ElKeVvlCb1VtMkhI",
      "google-site-verification=JO5hAUdeQB6RbQhV-_AKYyv6xfJnmVKuTkYtkZYhcLk",
      "google-site-verification=p_DY5uxkB0uAYklg-sR0Lii2bYnF6ZooXcw2Eyi4rL8",
      "docusign=828dd772-5bf2-4d4a-9956-c6b07049c55b",
      "facebook-domain-verification=rfrx5vjx0elz3n83h0ydr94nlkptkr",
      "atlassian-domain-verification=+SyUybAN4ilkkpHjnTS9UW9fhbIiAlFXshc97OU0IZw+UHVP0I9omo5Jzo7Qg7K+",
      "rippling-domain-verification=217697edd61756fc",
      "google-site-verification=3yHgeX--mAcr74szFR5gTbIbD1TkraSFdZS_xIm9jMY",
      "TAILSCALE-QTxUnggBiedjypLchTwB",
      "google-site-verification=GBizRM9Z_p17clZXSQMnJjIdyXLjCoDJY6aYG-kbwnQ",
      "mixpanel-domain-verify=3d34b526-2c05-4de4-a475-bdc5b58f49c8",
      "google-site-verification=1d_IjLk0hz3l3G9KrZeiLEIjloBhk0UKtyEIuGSmGa0",
      "MS=ms41162561",
      "google-site-verification=c6Hy78bVIo4EsMFlp02T8dC2rg_2s2kqhDdVkSQcNFQ",
      "v=spf1  include:mail.zendesk.com  include:_spf.sparkpostmail.com include:_spf.google.com include:amazonses.com include:spf.mandrillapp.com -all"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:reports@dmarc.bendingspoons.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.issuu.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R46 DV TLS CA 2026 Q3",
    "notBefore": "Aug 31 13:22:07 2026 GMT",
    "notAfter": "Mar 18 12:22:07 2027 GMT",
    "san": [
      "*.issuu.com",
      "issuu.com"
    ],
    "days_left": 174,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.65.55",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Issuu | Create Interactive Flipbooks on our Digital Publishing Platform"
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
      "origin": "https://sub.issuu.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://issuu.com/"
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
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 308
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 49.9,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
