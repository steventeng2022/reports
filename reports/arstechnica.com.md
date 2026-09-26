# Security Audit Report — arstechnica.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://arstechnica.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | arstechnica.com |
| Test date | 2026-09-26 18:46 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 4, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 8 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 9 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 18.190.166.196:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

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

### 7. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.arstechnica.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 8. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (qc9gmfgbrimtge.arstechnica.com and t9p697osyo6xeh.arstechnica.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 9. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=Xt1q2fpVK6qREDXADvlLz2O5pvmUz9G_xxoGdeEnrH0; google-site-verification=HdFEloOqFNJZvQWa7SK2BRmWVt8aVnPuagqXZ-C2U5U; google-site-verification=XuFuLW59WRoAbzeQ-wsF0JwpaeYwtdzRmtiktfi3Pmc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of arstechnica.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but arstechnica.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 34 disallow path(s), e.g. Allow:, User-agent:, /, /, /cgi-bin/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of arstechnica.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 18.190.166.196 carries PTR ec2-18-190-166-196.us-east-2.compute.amazonaws.com. for arstechnica.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "arstechnica.com",
  "dns": {
    "a": [
      "18.190.166.196",
      "77.112.68.204"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-1285.awsdns-32.org.",
      "ns-783.awsdns-33.net.",
      "ns-2008.awsdns-59.co.uk.",
      "ns-493.awsdns-61.com."
    ],
    "spf": [
      "google-site-verification=Xt1q2fpVK6qREDXADvlLz2O5pvmUz9G_xxoGdeEnrH0",
      "v=spf1 include:_u.arstechnica.com._spf.smart.ondmarc.com ~all",
      "google-site-verification=HdFEloOqFNJZvQWa7SK2BRmWVt8aVnPuagqXZ-C2U5U",
      "google-site-verification=XuFuLW59WRoAbzeQ-wsF0JwpaeYwtdzRmtiktfi3Pmc",
      "yahoo-verification-key=bP+HO9s82IBxbotbnF/O1nN4Jo4VfFXq5JNFAPCK8+o=",
      "google-site-verification=nso4GHYIGZwo4gB6AoUxzJWkxOUdx83kbGeREAxnv3A",
      "google-site-verification=OtVm0j4Rqs4y10N827uQ_n8ZnMtO0vfqw1k5NCzaJvo",
      "facebook-domain-verification=qptjyerza2q11uv3fe6aay6hbsncr8",
      "loaderio=2fd6086b1c3ba926ae36db37131123f7"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; sp=reject; rua=mailto:a6816915@inbox.ondmarc.com; ruf=mailto:a6816915@inbox.ondmarc.com; adkim=r; aspf=r; fo=1; rf=afrf; ri=3600"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
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
    "days_left": 104,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "18.190.166.196",
    "open": [
      8080
    ]
  },
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
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=Xt1q2fpVK6qREDXADvlLz2O5pvmUz9G_xxoGdeEnrH0",
    "google-site-verification=HdFEloOqFNJZvQWa7SK2BRmWVt8aVnPuagqXZ-C2U5U",
    "google-site-verification=XuFuLW59WRoAbzeQ-wsF0JwpaeYwtdzRmtiktfi3Pmc",
    "yahoo-verification-key=bP+HO9s82IBxbotbnF/O1nN4Jo4VfFXq5JNFAPCK8+o=",
    "google-site-verification=nso4GHYIGZwo4gB6AoUxzJWkxOUdx83kbGeREAxnv3A"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20260625000000",
      "not_after": "20270108235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "Allow:",
      "User-agent:",
      "/",
      "/",
      "/cgi-bin/",
      "/wp/wp-admin/",
      "/wp/wp-includes/",
      "/wp/wp-content/",
      "/wp-content/plugins/",
      "/wp-content/mu_plugins/",
      "/wp-content/cache/",
      "/wp-content/themes/",
      "/trackback/",
      "/comments/",
      "/category/*/*"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "ec2-18-190-166-196.us-east-2.compute.amazonaws.com."
    ]
  },
  "elapsed_s": 37.7,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
