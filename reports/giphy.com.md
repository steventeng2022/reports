# Security Audit Report — giphy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://giphy.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | giphy.com |
| Test date | 2026-09-26 17:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | CT1 | 25 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 17 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443";ma=86400,h3-29=":443";ma=86400,h3-27=":443";ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=15465600 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: apple-domain-verification=Fii0eNOZHns9TIAc; atlassian-domain-verification=2ZiBk8nroSamkeHuamMoEH9zYMfA1R0XO1ZWlq1mnt3E02TV0e; google-site-verification=wWrXYq5cDpNdZjgDPtJ30mM87mlOArvOCGrkEVndkko
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of giphy.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but giphy.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 2 disallow path(s), e.g. /gifs, /
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] 25 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.giphy.com, beta.giphy.com, blog.giphy.com, dev.giphy.com, media.giphy.com, status.giphy.com, support.giphy.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 17. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: beta.giphy.com, dev.giphy.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "giphy.com",
  "dns": {
    "a": [
      "151.101.1.55",
      "151.101.193.55",
      "151.101.65.55",
      "151.101.129.55"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "aspmx2.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-1507.awsdns-60.org.",
      "ns-1872.awsdns-42.co.uk.",
      "ns-688.awsdns-22.net.",
      "ns-8.awsdns-01.com."
    ],
    "spf": [
      "apple-domain-verification=Fii0eNOZHns9TIAc",
      "atlassian-domain-verification=2ZiBk8nroSamkeHuamMoEH9zYMfA1R0XO1ZWlq1mnt3E02TV0eaz56swmTVIdMH3",
      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1eUbX0WlXcwRefEWDxiZRQI59QABCL+n7ynL/9jASPtr4Nhlqff+AbbImJ7OgWkd6viDUk5RNsafT5dhtjGZTRLooTp2C1UWev9vIM5VBU4MIcW9ZGHuhTNrKPwiLS/TxJAFSE1lGWHmBp0+21XmdMbF/kF8k9WioazM093qmHwIDAQAB",
      "TAILSCALE-S8njngbH6JUB9eUyI3hA",
      "google-site-verification=wWrXYq5cDpNdZjgDPtJ30mM87mlOArvOCGrkEVndkko",
      "openai-domain-verification=dv-Sagm5Hc2GH6IccoTx7kqsIPO",
      "v=spf1 include:sendgrid.net include:_spf.google.com include:_spf.mailgun.org include:_spf.eu.mailgun.org include:servers.mcsv.net exists:%{i}._spf.mta.salesforce.com -all",
      "status-page-domain-verification=9qs86qrhsgnd",
      "00D1U000000q2bj=1TBWj00000001gr",
      "google-site-verification=m6PPLfObSkbjxTzE2TMYuB8ep11oITy1i3O2GqkEQ3A",
      "google-site-verification=84mKsZZUB9XYo-Ci3C6ODMErVHAtxe317JWYTbUQjFw"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:add78bd9e2@rua.easydmarc.us,mailto:dmarc@giphy.com; ruf=mailto:dmarc-reports@shutterstock.com; rf=afrf"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.giphy.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2026 Q2",
    "notBefore": "Apr 25 23:03:15 2026 GMT",
    "notAfter": "Nov 10 22:03:15 2026 GMT",
    "san": [
      "*.giphy.com",
      "giphy.com"
    ],
    "days_left": 45,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.1.55",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "GIPHY - Be Animated"
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
      "origin": "https://sub.giphy.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://giphy.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 403,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 25,
    "notable": [
      "api.giphy.com",
      "beta.giphy.com",
      "blog.giphy.com",
      "dev.giphy.com",
      "media.giphy.com",
      "status.giphy.com",
      "support.giphy.com"
    ],
    "sample": [
      "ads.giphy.com",
      "api.giphy.com",
      "arts.giphy.com",
      "beta.giphy.com",
      "blog.giphy.com",
      "cookies.giphy.com",
      "dev.giphy.com",
      "engineering.giphy.com",
      "eot.giphy.com",
      "giphy-analytics.giphy.com",
      "giphy.com",
      "giphyads.giphy.com",
      "kong.giphy.com",
      "media.giphy.com",
      "media0.giphy.com",
      "media1.giphy.com",
      "media2.giphy.com",
      "media3.giphy.com",
      "media4.giphy.com",
      "pingback.giphy.com"
    ],
    "dangling": [
      "beta.giphy.com",
      "dev.giphy.com"
    ]
  },
  "apex_txt": [
    "apple-domain-verification=Fii0eNOZHns9TIAc",
    "atlassian-domain-verification=2ZiBk8nroSamkeHuamMoEH9zYMfA1R0XO1ZWlq1mnt3E02TV0e",
    "google-site-verification=wWrXYq5cDpNdZjgDPtJ30mM87mlOArvOCGrkEVndkko",
    "openai-domain-verification=dv-Sagm5Hc2GH6IccoTx7kqsIPO",
    "status-page-domain-verification=9qs86qrhsgnd"
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
      "/gifs",
      "/"
    ]
  },
  "elapsed_s": 17.8,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
