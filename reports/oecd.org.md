# Security Audit Report — oecd.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://oecd.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | oecd.org |
| Test date | 2026-09-25 23:12 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 4, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | info | CT1 | 124 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 10 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [INFO] 124 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.oecd.org, api.one-pp.oecd.org, api.one.oecd.org, login.my.oecd.org, login.oecd.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 10. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: login.my.oecd.org; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "oecd.org",
  "dns": {
    "a": [
      "151.101.67.10",
      "151.101.3.10",
      "151.101.131.10",
      "151.101.195.10"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "oecd-org.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns1-03.azure-dns.com.",
      "ns4-03.azure-dns.info.",
      "ns2-03.azure-dns.net.",
      "ns3-03.azure-dns.org."
    ],
    "spf": [
      "MS=ms12713444",
      "docusign=26a8c1aa-ac33-45f2-9a60-8d2cd96d4b3d",
      "google-site-verification=SDEWojQdWXNif-TLtOo9erhxfQLpv29GSU6XhHK1r68",
      "2b065714-2fc1-4d13-b11f-08fbc02c7626",
      "google-site-verification=ywMTwu2FAsfR60NR80rZ3jMdv8Ku-rr1NVnMGvor75k",
      "d122tnk0lmcb7fw4lzdcvqmw9jdf4qqb",
      "v=spf1 ip4:78.41.128.0/22 include:spf.protection.outlook.com -all",
      "apple-domain-verification=Z7TTmRtTMuoxrVa2",
      "3f6aa5c46d2a4da482b5cb56af96dec1",
      "_c4vs31pucag8knkqzie5i90hhnstnug",
      "adobe-idp-site-verification=fe3732a56cceead6122113a39f9385a693c3367314cdad48789e5cfbf77d5977",
      "openai-domain-verification=dv-TmLkx83mPP4k3cYF7dEcKasX",
      "hpe-greenlake-domain-verification=4677486a4449536d6173586553475a59354f6761314d47683048313635694334",
      "v/l2fKfgQ+sfAM7ZccgEU41dgW0s412pftzTh7XJzyim4AUo1Wi2WVai364FALz09lut6gJWcS8YLtAjbkatrA==",
      "cisco-ci-domain-verification=295dc971d1c6be2b5403477737c89eac7ec07601440a1e0855e475c20aa08f68",
      "docusign=4a7be657-e630-44fc-87ba-b68287ac2a3d"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:mailincidentreport@oecd.org; ruf=mailto:mailincidentreport@oecd.org; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=FR, localityName=Paris, organizationName=Organisation for Economic Co-operation and Development, commonName=*.oecd.org",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Oct 16 00:00:00 2025 GMT",
    "notAfter": "Nov 16 23:59:59 2026 GMT",
    "san": [
      "*.oecd.org",
      "oecd.org"
    ],
    "days_left": 52,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.67.10",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [
    {}
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.oecd.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://oecd.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 403,
    "/api/": 301
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 124,
    "notable": [
      "api.oecd.org",
      "api.one-pp.oecd.org",
      "api.one.oecd.org",
      "login.my.oecd.org",
      "login.oecd.org"
    ],
    "sample": [
      "algobank-pp.oecd.org",
      "algobank.oecd.org",
      "aopkb.oecd.org",
      "api-dev.oecd.org",
      "api-pp.oecd.org",
      "api-st.oecd.org",
      "api.oecd.org",
      "api.one-pp.oecd.org",
      "api.one.oecd.org",
      "bo.oecd.org",
      "co.westernbalkans-competitiveness.oecd.org",
      "community.oecd.org",
      "cts-test-digicert.oecd.org",
      "cts-test-entrust.oecd.org",
      "cts-test-globalsign.oecd.org",
      "cts-test-thawte.oecd.org",
      "data-explorer-pp.oecd.org",
      "data-explorer.oecd.org",
      "data-viewer-pp.oecd.org",
      "data-viewer.oecd.org"
    ],
    "dangling": [
      "login.my.oecd.org"
    ]
  },
  "elapsed_s": 45.6,
  "rechecked": "2026-09-25 23:12 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
