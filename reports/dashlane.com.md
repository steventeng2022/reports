# Security Audit Report — dashlane.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dashlane.com/ |
| Bug bounty program | Dashlane |
| Listed scope domain | dashlane.com |
| Test date | 2026-09-25 09:12 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 2, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.27.218:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.27.218:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 9. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "dashlane.com",
  "dns": {
    "a": [
      "104.18.27.218",
      "104.18.26.218"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-396.awsdns-49.com.",
      "ns-1838.awsdns-37.co.uk.",
      "ns-646.awsdns-16.net.",
      "ns-1381.awsdns-44.org."
    ],
    "spf": [
      "stripe-verification=F6D326204AE8297C7C1DCE7B72D865C2DF049FEF4E46AA6BACEE6316D87F404F",
      "0ed1fe018a052438ee880c4b2fb7f1796949e855a2",
      "_klajo684kaqqtg2dul51ana7m7aol1s",
      "CKO=cli_mi3ag5v4v5ie3fcimbb5zcjkdi",
      "v=spf1 include:_spf.google.com include:spf2.dashlane.com include:mail.zendesk.com include:mktomail.com include:mg-spf.greenhouse.io include:_spf.salesforce.com -all",
      "1|www.dashlane.com",
      "google-site-verification=ozFOOl99Gxv4y-55zHWOduavfcmZEXqS1yR_CDVmupI",
      "ca3-3ad4d01464cb4caaad75392931cf4b49",
      "atlassian-domain-verification=RFwRELa7WvbbTQW5f6j9hPJUSLTAovvSepABK6YwHaeC6AcZtml0apL64eQFCdNQ",
      "openai-domain-verification=dv-4e55Awe1PWzWlnozKcMcHLLN",
      "jamf-site-verification=i2cgTr97X6Qxa-MZy8gprA",
      "KOmW3ca2DpgwtUwRLQ4RHREFYMTccYEbcgnu7ipuO8syoAZI6C3u7zcGX8zAw9ssJDdffzxQinO7UJCu3PvDdA==",
      "google-site-verification=yS6BK31Z2KXSj9dmrqfPzPshkE7b32wulJmzfiz4EUY",
      "wrike-verification=MjM0Nzk4OTpkODUzOWI2ZTk1ZjgyOWUxZDE2MDBmMWIyNmUxODUwODdiMTdkYjA5MjgyNjY3YjEwNmI2NzFmNTcyZjJiZGEz",
      "ca3-f1f15d7cb167404ab9c514c3b87529c0",
      "ca3-8b5b3457e553481da2ecf93bdf264443",
      "MS=ms78056367",
      "stripe-verification=237c0c2be4be590e020173f0d294be75fc3de8a6271806f084d2018b62d33372",
      "detectify-verification=19ea3dd383daec40adcb74a7968825b8",
      "google-site-verification=6lT65mGzmxxPStSgeiblmtFtT4u5V3PJYdIJ2dFu5So",
      "_yqvhaiv5owhbgbsa4qdcii7szjyce9m",
      "drift-domain-verification=3e92a53ea6894b4f337d741ba27c2ab31c8630fc4eed6403e438a4fdfb162a02",
      "anthropic-domain-verification-7k1h5w=lnSRFRHXgc8eyEwyyyEs0MZTE",
      "miro-verification=36887a2acef64995e895317181e786f8fbc6ce21"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=r; rua=mailto:dmarc-reports@dashlane.com; ruf=mailto:dmarc-reports@dashlane.com; rf=afrf; pct=100; ri=86400"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=dashlane.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 23 18:43:28 2026 GMT",
    "notAfter": "Dec 22 19:43:05 2026 GMT",
    "san": [
      "dashlane.com",
      "check.dashlane.com",
      "*.check.dashlane.com"
    ],
    "days_left": 88,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.27.218",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "dashlane.com",
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
      "origin": "https://sub.dashlane.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://dashlane.com/"
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
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 67.2,
  "rechecked": "2026-09-25 10:43 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
