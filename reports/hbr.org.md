# Security Audit Report — hbr.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hbr.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hbr.org |
| Test date | 2026-09-26 18:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 4, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 8 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 9 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 15 | info | CT1 | 26 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 16 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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

### 7. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 8. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 9. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (17otiypw3jfsuc.hbr.org and dym6wtb09oi4m5.hbr.org) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=0fyEgLpijqbt_OMG0ncBIK4G153eKqHF7UeGfTZgZk0; facebook-domain-verification=hvrm85rd5hvr18o50vzpd1lprkjg76; extensis-domain-verification=3decd987-0352-469b-8111-a273b429588a
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of hbr.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but hbr.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 26 disallow path(s), e.g. /resources/, /fastanswers, /my-library*, /email-colleague/, /add-to-cart/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 65.9.180.27 carries PTR server-65-9-180-27.tpe53.r.cloudfront.net. for hbr.org.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 15. [INFO] 26 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: login.hbr.org, login.qa.hbr.org, store.hbr.org, store.qa.hbr.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 16. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: login.hbr.org; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "hbr.org",
  "dns": {
    "a": [
      "65.9.180.27",
      "65.9.180.80",
      "65.9.180.70",
      "65.9.180.29"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "usb-smtp-inbound-1.mimecast.com (pref 10)",
      "usb-smtp-inbound-2.mimecast.com (pref 10)"
    ],
    "ns": [
      "ns-604.awsdns-11.net.",
      "ns-469.awsdns-58.com.",
      "ns-1175.awsdns-18.org.",
      "ns-1877.awsdns-42.co.uk."
    ],
    "spf": [
      "google-site-verification=0fyEgLpijqbt_OMG0ncBIK4G153eKqHF7UeGfTZgZk0",
      "facebook-domain-verification=hvrm85rd5hvr18o50vzpd1lprkjg76",
      "extensis-domain-verification=3decd987-0352-469b-8111-a273b429588a",
      "webexdomainverification.4C675B8B1892B136E053AB06FC0A3F65=7b2ac320-8920-4cf1-826d-975f96f199cb",
      "lyncdiscover = seh3q1rpvadu98fpk213q7htq2",
      "google-site-verification=o-E502ZnlfSSAM2JRb0RUfIxROmYDcYVOZnzlVRknS0",
      "onetrust-domain-verification=0df7d79642a64b338bb91818045b158d",
      "docusign=59df337d-04fe-422f-bd8e-438fc3e80d21",
      "google-site-verification=P1JGD_hnkAqlxSPmsFW_M2nifpmJC2iBjnfmKi1uJCc",
      "v=spf1 ip4:167.89.5.215 include:hbsp.harvard.edu include:amazonses.com include:u12602457.wl208.sendgrid.net include:aspmx.sailthru.com include:_spf.bigcommerce.com ~all",
      "MS=ms51679339",
      "smartsheet-site-validation=76f6Fdn8EnnOgbwX-KcCnJ5Nj66wRUeo",
      "Wo71J1PNbWKkAikjb4WeqxCjBcNQwf6hcll0LJM6s9peRMF1ImcaCENQfddffLROaJY6wZHW2jrUsDNXC38vjg==",
      "google-site-verification=ikLo_eYH7jY56yB4qtVoDTxY9WUWl7NkUEsM-UB6DT0",
      "knowbe4-site-verification=f00a4d6e618b4a00b6f39e0b4c9e093f",
      "_1nl5kysnqxswpmo75e1u1fdcbs0fptr",
      "ciscocidomainverification=3a5e2e428cc891b6aef0b7598537338dd5c2bf8fe96326d58d87f62324dd9733",
      "openai-domain-verification=dv-yzIW4FvevpXrgKYrQ9Ndlm4V",
      "atlassian-domain-verification=5VnB9cXf8cZ+rqMksjlq1KyEzUSjGsBJ5irmtvOZtpwtq6AsKSs+jGHcKUhotODA",
      "sip=m699vbpan7kdoitobogsq38e1k"
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
    "ip": "65.9.180.27",
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
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=0fyEgLpijqbt_OMG0ncBIK4G153eKqHF7UeGfTZgZk0",
    "facebook-domain-verification=hvrm85rd5hvr18o50vzpd1lprkjg76",
    "extensis-domain-verification=3decd987-0352-469b-8111-a273b429588a",
    "webexdomainverification.4C675B8B1892B136E053AB06FC0A3F65=7b2ac320-8920-4cf1-826d",
    "google-site-verification=o-E502ZnlfSSAM2JRb0RUfIxROmYDcYVOZnzlVRknS0"
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
      "aia_ocsp": null,
      "not_before": "20260915000000",
      "not_after": "20270331235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/resources/",
      "/fastanswers",
      "/my-library*",
      "/email-colleague/",
      "/add-to-cart/",
      "/login*",
      "/shopping-cart/",
      "/shipping-payment",
      "/review-order",
      "/order/thank-you/",
      "/content/ipad/",
      "/newsletters*",
      "/product/recommended*",
      "/webinar-assessment",
      "/search*"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-65-9-180-27.tpe53.r.cloudfront.net."
    ]
  },
  "elapsed_s": 19.8,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
