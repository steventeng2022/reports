# Security Audit Report — arstechnica.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://arstechnica.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | arstechnica.com |
| Test date | 2026-09-25 08:01 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **6** (High: 0, Medium: 1, Low: 1, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | TLS2 | TLS certificate hostname mismatch | CWE-297 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [MEDIUM] TLS certificate hostname mismatch (`TLS2`)

- **CWE:** CWE-297
- **Detail:** TLS verification failed: _ssl.c:993: The handshake operation timed out
- **Recommendation:** Serve a certificate whose SAN covers arstechnica.com.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=2592000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 6. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "arstechnica.com",
  "dns": {
    "a": [
      "77.112.68.204",
      "18.217.85.125"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-1285.awsdns-32.org.",
      "ns-493.awsdns-61.com.",
      "ns-783.awsdns-33.net.",
      "ns-2008.awsdns-59.co.uk."
    ],
    "spf": [
      "google-site-verification=nso4GHYIGZwo4gB6AoUxzJWkxOUdx83kbGeREAxnv3A",
      "facebook-domain-verification=qptjyerza2q11uv3fe6aay6hbsncr8",
      "google-site-verification=HdFEloOqFNJZvQWa7SK2BRmWVt8aVnPuagqXZ-C2U5U",
      "google-site-verification=Xt1q2fpVK6qREDXADvlLz2O5pvmUz9G_xxoGdeEnrH0",
      "v=spf1 include:_u.arstechnica.com._spf.smart.ondmarc.com ~all",
      "yahoo-verification-key=bP+HO9s82IBxbotbnF/O1nN4Jo4VfFXq5JNFAPCK8+o=",
      "google-site-verification=XuFuLW59WRoAbzeQ-wsF0JwpaeYwtdzRmtiktfi3Pmc",
      "google-site-verification=OtVm0j4Rqs4y10N827uQ_n8ZnMtO0vfqw1k5NCzaJvo",
      "loaderio=2fd6086b1c3ba926ae36db37131123f7"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; sp=reject; rua=mailto:a6816915@inbox.ondmarc.com; ruf=mailto:a6816915@inbox.ondmarc.com; adkim=r; aspf=r; fo=1; rf=afrf; ri=3600"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "hostname-mismatch",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=*.arstechnica.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jun 25 00:00:00 2026 GMT",
    "notAfter": "Jan  8 23:59:59 2027 GMT",
    "san": [
      "*.arstechnica.com",
      "arstechnica.com"
    ],
    "days_left": 105
  },
  "elapsed_s": 17.9,
  "subdomains": {
    "status": "crt.sh 502 (certspotter 429)"
  },
  "rechecked": "2026-09-25 13:59 UTC",
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "Ars Technica - Serving the Technologist since 1998. News, reviews, and analysis."
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
      "origin": "https://sub.arstechnica.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://arstechnica.com:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
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
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  }
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
