# Security Audit Report — imgur.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://imgur.com/ |
| Bug bounty program | Imgur |
| Listed scope domain | imgur.com |
| Test date | 2026-09-25 09:52 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 10 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 11 | low | CORS1 | CORS: subdomain origin origin accepted with credentials | CWE-942 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cat factory 1.0
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=300 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cat factory 1.0
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'postpagebeta' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 10. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'postpagebeta' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 11. [LOW] CORS: subdomain origin origin accepted with credentials (`CORS1`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.imgur.com -> Access-Control-Allow-Origin: https://sub.imgur.com, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

## Evidence (raw response observations)

```json
{
  "domain": "imgur.com",
  "dns": {
    "a": [
      "199.232.196.193",
      "199.232.192.193"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-577.awsdns-08.net.",
      "ns-1677.awsdns-17.co.uk.",
      "ns-457.awsdns-57.com.",
      "ns-1198.awsdns-21.org."
    ],
    "spf": [
      "v=spf1 ip4:54.198.157.21 include:mailgun.org include:amazonses.com include:_spf.google.com include:mail.zendesk.com -all",
      "BSI106497997089",
      "MS=ms20045453",
      "postman-domain-verification=45da7b179f25335b9e65a9b8d26d2fcd0739b9a1bf830b954c8abffd4acdb020707de3ddae662ed12ce411cce3357a6bd5a50c30c82bf4c481e40632f12d6ba6",
      "d2jm6zv3c45cb6.cloudfront.net",
      "google-site-verification=BzDTAgIuFjEqDFJFvpiwwNkX9LD8RuDq_8VrW1DFJQc",
      "ZOOM_verify_7qYn368TOF6Au0Hn7KWJ2P",
      "google-site-verification=jZetkGMTS63ZvRLFkjDNglMVkFkR-cZYwysKhIcg1S4",
      "perplexity-ai-domain-verification-rcshp6=bIjE0TyYQyGqn2X0tjlqweDO0",
      "atlassian-domain-verification=zBnQjyxIXRiBvnX39OwQsQjQ0NHRTT8z7jLkSYoDwQI0LDJEbkHtP50JXc/nBUSm",
      "mixpanel-domain-verify=877fb4f7-e334-4b13-9770-1bec2610bf63",
      "google-site-verification=Kh_iAw1AcwclD3rmGP7pOJp0zBgCwcW1V-L-mUXHMls",
      "1password-site-verification=BSXZBGRLX5ETBE6LCXUXT3ZACE",
      "xf6t3vb8tjqqgypgpbw0bdmk98z49dk9",
      "google-site-verification=lkg-LO7WaYRV1KFiztrPou_kY0KNS_h7c2nuhfia-ko"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc@imgur.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=*.imgur.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA DV R36",
    "notBefore": "Feb 13 00:00:00 2026 GMT",
    "notAfter": "Feb 15 23:59:59 2027 GMT",
    "san": [
      "*.imgur.com",
      "imgur.com"
    ],
    "days_left": 143,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "199.232.196.193",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "Imgur: The magic of the Internet"
  },
  "mixed_content": [],
  "tech": [
    "Server: cat factory 1.0"
  ],
  "cookies": [
    {
      "domain": ".imgur.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "https://imgur.com",
      "acac": "false"
    },
    {
      "origin": "https://sub.imgur.com",
      "acao": "https://sub.imgur.com",
      "acac": "true"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://imgur.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
    "/.git/HEAD": 200,
    "/.git/config": 200,
    "/.env": 200,
    "/.htaccess": 200,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 404,
    "/server-status": 301,
    "/api/": 404
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 33.8,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
