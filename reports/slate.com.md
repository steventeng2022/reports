# Security Audit Report — slate.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://slate.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | slate.com |
| Test date | 2026-09-26 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 2, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | low | CORS1 | CORS: subdomain origin origin accepted with credentials | CWE-942 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 8 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 9 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443";ma=86400,h3-29=":443";ma=86400,h3-27=":443";ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [LOW] CORS: subdomain origin origin accepted with credentials (`CORS1`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.slate.com -> Access-Control-Allow-Origin: https://sub.slate.com, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

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

### 9. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=RtXv6uaEMMbRyleHa5jMbQmiUCVy0CxH4Qf3lF/s3fImwTlXN0; anthropic-domain-verification-c0vb92=wY93HN3anBHD2OlT4k2zb6uxk; brave-ledger-verification=5afa57fd13cda982bccc0b089e0ec3a815cdaa816111719c956146
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of slate.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but slate.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 12 disallow path(s), e.g. /search, /comments/, /_, /, /search
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "slate.com",
  "dns": {
    "a": [
      "151.101.129.55",
      "151.101.193.55",
      "151.101.65.55",
      "151.101.1.55"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-625.awsdns-14.net.",
      "ns-259.awsdns-32.com.",
      "ns-1512.awsdns-61.org.",
      "ns-1786.awsdns-31.co.uk."
    ],
    "spf": [
      "atlassian-domain-verification=RtXv6uaEMMbRyleHa5jMbQmiUCVy0CxH4Qf3lF/s3fImwTlXN0Cda4AoqkamJwM2",
      "anthropic-domain-verification-c0vb92=wY93HN3anBHD2OlT4k2zb6uxk",
      "brave-ledger-verification=5afa57fd13cda982bccc0b089e0ec3a815cdaa816111719c9561464e072ca8a6",
      "facebook-domain-verification=h1bqpgb101ufjdlpv4m8n6js8pjbde",
      "apple-domain-verification=sZMSDmtoSKwsMe0p",
      "v=spf1 include:aspmx.sailthru.com include:_spf.google.com include:spf.mandrillapp.com a mx ~all",
      "0Rzz3Kx9ec13bCErlJnYMmfVDdoBx/Ia5ft9GkYWliQoqA6yBu19ikpGi5TA/I6AI4oBnFMAHGVZ1+cPRgzoIg==",
      "google-site-verification=uArxK1vn-yOFkOmDQ2CSIPUjMlYZVXsYoMi3YdoMUB8",
      "yahoo-verification-key=ogjPBpuuDDUAAigNW0C+1x8mbNmcXH/fwMxATyGt1B4=",
      "MS=ms80887413"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; ri=3600; rua=mailto:iyu10eqj@ag.us.dmarcian.com; ruf=mailto:dmarc_ruf@slate.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=slate.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Sep 15 20:03:09 2026 GMT",
    "notAfter": "Dec 14 20:03:08 2026 GMT",
    "san": [
      "slate.com"
    ],
    "days_left": 79,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.129.55",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Slate Magazine - Politics, Business, Technology, and the Arts"
  },
  "mixed_content": [
    "href=\"http://"
  ],
  "cookies": [
    {
      "samesite": "strict"
    },
    {
      "samesite": "strict"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.slate.com",
      "acao": "https://sub.slate.com",
      "acac": "true"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://slate.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 302
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "atlassian-domain-verification=RtXv6uaEMMbRyleHa5jMbQmiUCVy0CxH4Qf3lF/s3fImwTlXN0",
    "anthropic-domain-verification-c0vb92=wY93HN3anBHD2OlT4k2zb6uxk",
    "brave-ledger-verification=5afa57fd13cda982bccc0b089e0ec3a815cdaa816111719c956146",
    "facebook-domain-verification=h1bqpgb101ufjdlpv4m8n6js8pjbde",
    "apple-domain-verification=sZMSDmtoSKwsMe0p"
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
      "/search",
      "/comments/",
      "/_",
      "/",
      "/search",
      "/comments/",
      "/_",
      "/css",
      "/fonts",
      "/media",
      "/piano",
      "/static"
    ]
  },
  "elapsed_s": 16.4,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
