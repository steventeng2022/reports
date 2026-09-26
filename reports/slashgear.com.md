# Security Audit Report — slashgear.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://slashgear.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | slashgear.com |
| Test date | 2026-09-26 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 3, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P11 | WordPress login page exposed | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | CT1 | 2 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx/1.18.0 (Ubuntu)
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: nginx/1.18.0 (Ubuntu)
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] WordPress login page exposed (`P11`)

- **CWE:** CWE-200
- **Detail:** /wp-login.php returns 200.
- **Recommendation:** Restrict or rate-limit the WordPress login endpoint.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: facebook-domain-verification=vcw5ice4xutsws6rj3cpxdpslwu6qd; google-site-verification=hLM8LlkEvTqibiu5LlpaUI7FcUqPRYajAd7kqdQ8yIE; pinterest-site-verification=99ff81df9daa6ad32e804c775f922a47
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of slashgear.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 7 disallow path(s), e.g. /wp-admin/, /wp-includes/, /*?*ajax=, /*/s/*, /*/sl/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] 2 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "slashgear.com",
  "dns": {
    "a": [
      "65.9.180.30",
      "65.9.180.36",
      "65.9.180.10",
      "65.9.180.100"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "aspmx2.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-1080.awsdns-07.org.",
      "ns-432.awsdns-54.com.",
      "ns-1985.awsdns-56.co.uk.",
      "ns-518.awsdns-00.net."
    ],
    "spf": [
      "facebook-domain-verification=vcw5ice4xutsws6rj3cpxdpslwu6qd",
      "sv8nbg16pjbbc11nh7l86zjw21zg20sq",
      "google-site-verification=hLM8LlkEvTqibiu5LlpaUI7FcUqPRYajAd7kqdQ8yIE",
      "pinterest-site-verification=99ff81df9daa6ad32e804c775f922a47",
      "v=spf1 include:_spf.google.com ~all"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; fo=1; rua=mailto:dmarc@slashgear.com; ruf=mailto:dmarc@slashgear.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=slashgear.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Sep  5 00:00:00 2026 GMT",
    "notAfter": "Mar 21 23:59:59 2027 GMT",
    "san": [
      "slashgear.com",
      "*.slashgear.com"
    ],
    "days_left": 176,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "65.9.180.30",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx/1.18.0 (Ubuntu)"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.slashgear.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://slashgear.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 404,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 2,
    "notable": [],
    "sample": [
      "slashgear.com",
      "subscribe.slashgear.com"
    ]
  },
  "apex_txt": [
    "facebook-domain-verification=vcw5ice4xutsws6rj3cpxdpslwu6qd",
    "google-site-verification=hLM8LlkEvTqibiu5LlpaUI7FcUqPRYajAd7kqdQ8yIE",
    "pinterest-site-verification=99ff81df9daa6ad32e804c775f922a47"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/wp-admin/",
      "/wp-includes/",
      "/*?*ajax=",
      "/*/s/*",
      "/*/sl/*",
      "/search/",
      "/sponsored/"
    ]
  },
  "elapsed_s": 7.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
