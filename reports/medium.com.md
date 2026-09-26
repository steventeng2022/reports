# Security Audit Report — medium.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://medium.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | medium.com |
| Test date | 2026-09-26 18:55 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 2, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 11 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 12 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.152.4:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.152.4:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 9. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 10. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (f48s9h9ul1kwai.medium.com and xrkt4z7dzlc00l.medium.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 11. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: anthropic-domain-verification-p32bnn=TlzaDtedEYyM5ccLdU8NsQIPP; linear-domain-verification=tyjcyfd4thj2; cursor-domain-verification-54pwxn=8yHL5J3FELu0JwETv8iGeZt4A
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 12. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of medium.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 16 disallow path(s), e.g. /m/, /me/, /@me$, /@me/, /*/edit$
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of medium.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

## Evidence (raw response observations)

```json
{
  "domain": "medium.com",
  "dns": {
    "a": [
      "162.159.152.4",
      "162.159.153.4"
    ],
    "aaaa": [
      "2606:4700:7::a29f:9804",
      "2606:4700:7::a29f:9904"
    ],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "aspmx3.googlemail.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)"
    ],
    "ns": [
      "kip.ns.cloudflare.com.",
      "alina.ns.cloudflare.com."
    ],
    "spf": [
      "anthropic-domain-verification-p32bnn=TlzaDtedEYyM5ccLdU8NsQIPP",
      "linear-domain-verification=tyjcyfd4thj2",
      "cursor-domain-verification-54pwxn=8yHL5J3FELu0JwETv8iGeZt4A",
      "yahoo-verification-key=nOxcdTfSy6txWr8ZAJ8EevOZHdrxuX4qFKljmgTLsu8=",
      "google-site-verification=QuRrrbvTtvFC0uq2BLr_CcuuuDEiNGDJjI7XkPV3s60",
      "google-site-verification=jUulFqySbosf7Fvi1pvOm1KL3AeQ5L5s18CDIU30xek",
      "google-site-verification=TUaeSBwTARWW1ntR_TLK0FwD5WKnFCpB5gYVuXkBmlg",
      "dropbox-domain-verification=d7wsnlvbz6l3",
      "google-site-verification=nlPBDLGxOufYa5DdXnQ8d28h5dJjwy0bSakZq-tSios",
      "notion-domain-verification=FPUVTTLhldYnVqE4496kGbBhDpf54Y4O7eA8SxkbAHk",
      "07ecf60c9da442a9b3bcce99190ff60a",
      "google-site-verification=qmNSvk4iAfYY_fZYv821myqWI4vaInKsGaBTkg4wNRw",
      "Domain Verification for Digicert (10/05/2022)y7ncgbyk39tw482zsbwcnfx0t775d85j",
      "v=spf1 include:amazonses.com include:_spf.google.com include:mail.zendesk.com include:sendgrid.net include:spf.tipalti.com include:_spf.psm.knowbe4.com ~all",
      "apple-domain-verification=Ls6JkesM8aOd8xyQ",
      "facebook-domain-verification=eqviiajbkkhum35vciytgngt69oan0",
      "openai-domain-verification=dv-G8sPcKCsIq9tKkWTNFJZh3RE"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; fo=1; ri=3600; rua=mailto:dmarc.rua@medium.com,mailto:dmarc_agg@vali.email; ruf=mailto:dmarc.rua@medium.com,mailto:ruf@dmarc.medium.com,mailto:dmarc_agg@vali.email;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=medium.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep  5 20:48:04 2026 GMT",
    "notAfter": "Dec  4 21:48:00 2026 GMT",
    "san": [
      "medium.com",
      "*.medium.com"
    ],
    "days_left": 69,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "162.159.152.4",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.medium.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://medium.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 403,
    "/security.txt": 403,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "anthropic-domain-verification-p32bnn=TlzaDtedEYyM5ccLdU8NsQIPP",
    "linear-domain-verification=tyjcyfd4thj2",
    "cursor-domain-verification-54pwxn=8yHL5J3FELu0JwETv8iGeZt4A",
    "yahoo-verification-key=nOxcdTfSy6txWr8ZAJ8EevOZHdrxuX4qFKljmgTLsu8=",
    "google-site-verification=QuRrrbvTtvFC0uq2BLr_CcuuuDEiNGDJjI7XkPV3s60"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260905204804",
      "not_after": "20261204214800"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/m/",
      "/me/",
      "/@me$",
      "/@me/",
      "/*/edit$",
      "/*/*/edit$",
      "/media/",
      "/p/*/share",
      "/r/",
      "/trending",
      "/search?q$",
      "/search?q=",
      "/*/search?q=",
      "/*/search/*?q=",
      "/*/*source="
    ]
  },
  "x12": {
    "status": 403
  },
  "elapsed_s": 4.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
