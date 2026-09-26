# Security Audit Report — ameblo.jp

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ameblo.jp/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ameblo.jp |
| Test date | 2026-09-25 07:50 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 2, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | info | CT1 | 17 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [INFO] 17 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: dev.ameblo.jp, image.portal.ameblo.jp
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "ameblo.jp",
  "dns": {
    "a": [
      "199.232.214.133",
      "199.232.210.133"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mail.ameblo.jp (pref 10)"
    ],
    "ns": [
      "ns-863.awsdns-43.net.",
      "ns-2038.awsdns-62.co.uk.",
      "ns-124.awsdns-15.com.",
      "ns-1218.awsdns-24.org."
    ],
    "spf": [
      "google-site-verification=fst_3JQsVLfa2f0Df-x-KdG2tW23U3jDz09k6iF__y8",
      "cPu1ZpFdt7xvQjanmhmE12k4AmF0MH",
      "fastly-domain-delegation-@X7yV19EoO6Y-2023-06-30",
      "_mnobpm3nakzeekpqy6i72p451qgv326",
      "_gmqf0w3hsh1pqlogfw1gkg05zhs88zx",
      "tollbit-domain-verification=e5f400b7a9ee16a9c039d5a7c1ca7587cf4d1c4708b2193bfa9778f5ed1c8d42",
      "v=spf1 ip4:216.255.232.136/32 include:spf-a.ameba.jp include:spf.repica.jp -all",
      "google-site-verification=26Ps67bWgQGjeNkTT6hV9VEgczhnzjN78yCdM33v-eo",
      "UHgEILc96z9sKmvYTwgZYiwusQbyqI",
      "fastly-domain-delegation-nfkcslan-542735-2022-10-31"
    ],
    "dmarc": [
      "v=DMARC1; p=none"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "countryName=JP, stateOrProvinceName=Tokyo, localityName=Shibuya-ku, organizationName=CyberAgent, Inc., commonName=*.ameblo.jp",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=GeoTrust TLS RSA CA G1",
    "notBefore": "Aug  3 00:00:00 2026 GMT",
    "notAfter": "Feb 16 23:59:59 2027 GMT",
    "san": [
      "*.ameblo.jp",
      "ameblo.jp"
    ],
    "days_left": 144,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "199.232.214.133",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "アメーバブログ（アメブロ）｜Amebaで無料ブログを始めよう"
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
      "origin": "https://sub.ameblo.jp",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ameblo.jp/"
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
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 301,
    "/api/": 200
  },
  "subdomains": {
    "source": "certspotter",
    "count": 17,
    "notable": [
      "dev.ameblo.jp",
      "image.portal.ameblo.jp"
    ],
    "sample": [
      "ameblo.jp",
      "dev-blog.ameblo.jp",
      "dev-ml.ameblo.jp",
      "dev.ameblo.jp",
      "image.portal.ameblo.jp",
      "mamade-shop.ameblo.jp",
      "meandre-shop.ameblo.jp",
      "ml.ameblo.jp",
      "polun-shop.ameblo.jp",
      "stg-ml.ameblo.jp",
      "stg-org-sy.ameblo.jp",
      "stg-sy.ameblo.jp",
      "stg.ameblo.jp",
      "stg.sy.ameblo.jp",
      "sy.ameblo.jp",
      "tollbit.ameblo.jp",
      "zt.ameblo.jp"
    ]
  },
  "elapsed_s": 111.8,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
