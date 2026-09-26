# Security Audit Report — acm.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://acm.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | acm.org |
| Test date | 2026-09-26 18:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 4, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 7 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 8 | low | H2 | Missing CSP header | CWE-1021 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 20 days (notAfter Oct 16 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.17.79.30:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.17.79.30:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 7. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=0 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 8. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.acm.org/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=lqxyh1_UaHYvgAfZ3gvxIDJi3quBVO_5Lq_pDUOKdNw; duo_sso_verification=oFRYT7Y1MADnakU5K1wxwe47F9TsTRZ76IZL8bgH2J0NFoipvgi5tAE6kTm; abuseipdb-verification=D4c0J6WF
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of acm.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but acm.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 18 disallow path(s), e.g. /live-search, /404, /landing-page-documents/, /referenced-ctalist/, /Member/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "acm.org",
  "dns": {
    "a": [
      "104.17.79.30",
      "104.17.78.30"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mail.mailroute.net (pref 10)"
    ],
    "ns": [
      "olga.ns.cloudflare.com.",
      "skip.ns.cloudflare.com."
    ],
    "spf": [
      "3w6lthcz5h4qpgtd8n8szx1m474v73tz",
      "google-site-verification=lqxyh1_UaHYvgAfZ3gvxIDJi3quBVO_5Lq_pDUOKdNw",
      "brevo-code:e7393522d4f06661f44afbccb0cebfc6",
      "MS=F1C3025E76F2E7036C9EAF6DBC2DF0C8D2D4AA87",
      "duo_sso_verification=oFRYT7Y1MADnakU5K1wxwe47F9TsTRZ76IZL8bgH2J0NFoipvgi5tAE6kTmlRfY8",
      "abuseipdb-verification=D4c0J6WF",
      "google-site-verification=8gUY1AtsZ3BzLVSHLSv3wXIE8MpnWrGgVrmvVxM1MjE",
      "_ead5vviqjla5mjijrh4zvhsujcx843n",
      "_isyuzeobyu2bijfg78028dab2ac4f5r",
      "p0yygcm8ljrr9v47xkgrk4cjdvpctb6t",
      "83zn0ndgz9jvwx563vp9qbyz38hqb7kl",
      "v=spf1 include:_spf.acm_org._d.easydmarc.pro ~all"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;sp=quarantine;pct=100;rua=mailto:9adb8cf49b@rua.easydmarc.us;ruf=mailto:9adb8cf49b@ruf.easydmarc.us;fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=Association for Computing Machinery, Inc., commonName=*.acm.org",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Apr  1 00:00:00 2026 GMT",
    "notAfter": "Oct 16 23:59:59 2026 GMT",
    "san": [
      "*.acm.org",
      "acm.org"
    ],
    "days_left": 20,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.17.79.30",
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
  "cookies": [
    {
      "domain": "acm.org",
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
      "origin": "https://sub.acm.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://acm.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=lqxyh1_UaHYvgAfZ3gvxIDJi3quBVO_5Lq_pDUOKdNw",
    "duo_sso_verification=oFRYT7Y1MADnakU5K1wxwe47F9TsTRZ76IZL8bgH2J0NFoipvgi5tAE6kTm",
    "abuseipdb-verification=D4c0J6WF",
    "google-site-verification=8gUY1AtsZ3BzLVSHLSv3wXIE8MpnWrGgVrmvVxM1MjE"
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
      "not_before": "20260401000000",
      "not_after": "20261016235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/live-search",
      "/404",
      "/landing-page-documents/",
      "/referenced-ctalist/",
      "/Member/",
      "/history-acm-org/",
      "/amturing-acm-org/",
      "/student-chapter-excellence-awards/",
      "/chapters/students/excellence-awards/",
      "/conferences/non-acm-events",
      "/conferences/conference-events",
      "/chapters/local-activities",
      "/award_winners",
      "/chapters.html",
      "/amg.html"
    ]
  },
  "x12": {
    "status": 403
  },
  "elapsed_s": 6.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
