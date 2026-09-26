# Security Audit Report — hbr.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hbr.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hbr.org |
| Test date | 2026-09-26 01:46 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 3, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | CT1 | 26 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 8 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=7776000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

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

### 7. [INFO] 26 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: login.hbr.org, login.qa.hbr.org, store.hbr.org, store.qa.hbr.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 8. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: login.hbr.org; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "hbr.org",
  "dns": {
    "a": [
      "65.9.180.29",
      "65.9.180.70",
      "65.9.180.27",
      "65.9.180.80"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "usb-smtp-inbound-2.mimecast.com (pref 10)",
      "usb-smtp-inbound-1.mimecast.com (pref 10)"
    ],
    "ns": [
      "ns-469.awsdns-58.com.",
      "ns-1877.awsdns-42.co.uk.",
      "ns-604.awsdns-11.net.",
      "ns-1175.awsdns-18.org."
    ],
    "spf": [
      "webexdomainverification.4C675B8B1892B136E053AB06FC0A3F65=7b2ac320-8920-4cf1-826d-975f96f199cb",
      "MS=ms51679339",
      "google-site-verification=ikLo_eYH7jY56yB4qtVoDTxY9WUWl7NkUEsM-UB6DT0",
      "_1nl5kysnqxswpmo75e1u1fdcbs0fptr",
      "google-site-verification=P1JGD_hnkAqlxSPmsFW_M2nifpmJC2iBjnfmKi1uJCc",
      "knowbe4-site-verification=f00a4d6e618b4a00b6f39e0b4c9e093f",
      "docusign=59df337d-04fe-422f-bd8e-438fc3e80d21",
      "Wo71J1PNbWKkAikjb4WeqxCjBcNQwf6hcll0LJM6s9peRMF1ImcaCENQfddffLROaJY6wZHW2jrUsDNXC38vjg==",
      "v=spf1 ip4:167.89.5.215 include:hbsp.harvard.edu include:amazonses.com include:u12602457.wl208.sendgrid.net include:aspmx.sailthru.com include:_spf.bigcommerce.com ~all",
      "onetrust-domain-verification=0df7d79642a64b338bb91818045b158d",
      "smartsheet-site-validation=76f6Fdn8EnnOgbwX-KcCnJ5Nj66wRUeo",
      "atlassian-domain-verification=5VnB9cXf8cZ+rqMksjlq1KyEzUSjGsBJ5irmtvOZtpwtq6AsKSs+jGHcKUhotODA",
      "openai-domain-verification=dv-yzIW4FvevpXrgKYrQ9Ndlm4V",
      "ciscocidomainverification=3a5e2e428cc891b6aef0b7598537338dd5c2bf8fe96326d58d87f62324dd9733",
      "lyncdiscover = seh3q1rpvadu98fpk213q7htq2",
      "extensis-domain-verification=3decd987-0352-469b-8111-a273b429588a",
      "sip=m699vbpan7kdoitobogsq38e1k",
      "google-site-verification=0fyEgLpijqbt_OMG0ncBIK4G153eKqHF7UeGfTZgZk0",
      "facebook-domain-verification=hvrm85rd5hvr18o50vzpd1lprkjg76",
      "google-site-verification=o-E502ZnlfSSAM2JRb0RUfIxROmYDcYVOZnzlVRknS0"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:ufwln6jz@ag.dmarcian.com; ruf=mailto:ufwln6jz@fr.dmarcian.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.hbr.org",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Sep 15 00:00:00 2026 GMT",
    "notAfter": "Mar 31 23:59:59 2027 GMT",
    "san": [
      "*.hbr.org",
      "hbr.org"
    ],
    "days_left": 186,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "65.9.180.29",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Harvard Business Review - Ideas and Advice for Leaders"
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
      "origin": "https://sub.hbr.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://hbr.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 403,
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
    "source": "certspotter",
    "count": 26,
    "notable": [
      "login.hbr.org",
      "login.qa.hbr.org",
      "store.hbr.org",
      "store.qa.hbr.org"
    ],
    "sample": [
      "advisorycouncil.hbr.org",
      "assessments.hbr.org",
      "audio.hbr.org",
      "coveo-analytics-qa.hbr.org",
      "coveo-analytics.hbr.org",
      "coveo-search-qa.hbr.org",
      "coveo-search.hbr.org",
      "execstrategy-dev.hbr.org",
      "execstrategy-sand.hbr.org",
      "execstrategy-stage.hbr.org",
      "execstrategy.hbr.org",
      "hbr.org",
      "lab.hbr.org",
      "link.emails.hbr.org",
      "link.hbr.org",
      "link.qa.hbr.org",
      "login.hbr.org",
      "login.qa.hbr.org",
      "qa.hbr.org",
      "research.hbr.org"
    ],
    "dangling": [
      "login.hbr.org"
    ]
  },
  "elapsed_s": 16.2,
  "rechecked": "2026-09-26 04:00 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
