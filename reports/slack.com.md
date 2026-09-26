# Security Audit Report — slack.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://slack.com/ |
| Bug bounty program | Slack |
| Listed scope domain | slack.com |
| Test date | 2026-09-25 10:15 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 2, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000, h3-29=":443"; ma=2592000, quic=":443"; ma=2592000
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

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Apache
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

## Evidence (raw response observations)

```json
{
  "domain": "slack.com",
  "dns": {
    "a": [
      "52.196.128.139",
      "35.74.58.174",
      "35.73.126.78",
      "52.192.46.121"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "aspmx3.googlemail.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-1901.awsdns-45.co.uk.",
      "ns-166.awsdns-20.com.",
      "ns-606.awsdns-11.net.",
      "ns-1493.awsdns-58.org."
    ],
    "spf": [
      "google-site-verification=o2grd1TLmZZ8GrqbhVIFtzO2MRLTtSUpBBIBYfhQVCQ",
      "google-site-verification=kB1KvgpSk9YkHsFmsj1VPI5YmDvfKctPxnplhGjyqtE",
      "v=spf1 include:_spf.qualtrics.com include:mail.zendesk.com include:_spfextra.slack.com -all",
      "google-site-verification=v-LLB__IhraaI7ZzuE3jvRFIm2vERPLzWoepAEZJtKQ",
      "google-site-verification=QvelFPjIOe3Vavw0q-aAVYaAPKmWCRjmmVVEAjgfjQc",
      "google-site-verification=efuXt5-oMr2CdNmVi6A9IO29KMKifpseD1qokxjWwcE",
      "spycloud-domain-verification=02e4c0be-cf43-44e4-beaf-4f99702ca632",
      "OSSRH-54733",
      "google-site-verification=2PK67oVPNyEtS1avSlr3PhH5nSiFuticbQv_bT4pM2k",
      "google-site-verification=KqX3Ngw0XEjz_0GVx_xwFFlCoO-bskhqU_lxv0Q77mk",
      "_0vidyxobp6x350odqhb4fo7fdxhmtq3",
      "hubspot-developer-verification=OTE4NzYxYTgtMDUwZi00MzgzLTk2YTUtZDAwNjBlODg1MWM0"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;fo=1:d:s;pct=100;rua=mailto:dmarc_agg@vali.email,mailto:0e5a5c34@inbox.ondmarc.com;ruf=mailto:0e5a5c34@inbox.ondmarc.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=slack.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug  6 09:33:39 2026 GMT",
    "notAfter": "Nov  4 09:33:38 2026 GMT",
    "san": [
      "*.slack.com",
      "slack.com"
    ],
    "days_left": 39,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "52.196.128.139",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Slack | AI Work Platform &amp; Productivity Tools"
  },
  "mixed_content": [],
  "tech": [
    "Server: Apache"
  ],
  "cookies": [
    {
      "domain": ".slack.com",
      "samesite": "none"
    },
    {
      "domain": ".slack.com",
      "samesite": "none"
    },
    {
      "domain": ".slack.com",
      "samesite": "none"
    },
    {
      "domain": ".slack.com",
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.slack.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://slack.com:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 33.9,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
