# Security Audit Report — snip.ly

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://snip.ly/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | snip.ly |
| Test date | 2026-09-26 18:59 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 3, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | CT1 | 10 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.47.26:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.47.26:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://snip.ly/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=E0-Y5g1NnmKsAykCJM_8ZcZ47F_kvKpiKqKBR8LAZjs; stripe-verification=b8f011424d7440301c08c6a96b963dff0ea2b19d949b49b27948a371ed29; google-site-verification=EMvnpww3LUyhGXCFgv6Dw6q-rTic9HE2PQYLq5MCz-4
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of snip.ly has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] 10 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: app.snip.ly, status.snip.ly, support.snip.ly
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "snip.ly",
  "dns": {
    "a": [
      "104.20.47.26",
      "172.66.148.43"
    ],
    "aaaa": [
      "2606:4700:10::ac42:942b",
      "2606:4700:10::6814:2f1a"
    ],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "lily.ns.cloudflare.com.",
      "alex.ns.cloudflare.com."
    ],
    "spf": [
      "v=spf1 include:_spf.snip_ly._d.easydmarc.pro -all",
      "google-site-verification=E0-Y5g1NnmKsAykCJM_8ZcZ47F_kvKpiKqKBR8LAZjs",
      "stripe-verification=b8f011424d7440301c08c6a96b963dff0ea2b19d949b49b27948a371ed2994ba",
      "google-site-verification=EMvnpww3LUyhGXCFgv6Dw6q-rTic9HE2PQYLq5MCz-4",
      "google-site-verification=Ff00bkXsoqs19-xOPGYHomnEZgewHP6MyNcSQxDOBNo",
      "google-site-verification=wr96MTDdDbqxCE3z7cewsOPGSCmGaVQC3z1qw4aooBk",
      "google-site-verification=lpAbHXGi3Apb8JCGCS5nG35CQgr10wnKJZJE5dpmFpg",
      "facebook-domain-verification=5m9fbpfl5izwhf2w9x5dxuswyooh1k",
      "google-site-verification=7fa0rEULAgTKYfy-zI-dubTiSbE9lfLpjUWjdD73a40",
      "google-site-verification=7zkA4yhKhcykMfCwPUGRMAnlNeia9anQAjzmKxbOzcE"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;pct=80;rua=mailto:217221592c@rua.easydmarc.us,mailto:9e3a858cf6aa44c5a08cd174ef664b53@dmarc-reports.cloudflare.net,mailto:a41f5123@mxtoolbox.dmarc-report.com;ruf=mailto:217221592c@ruf.easydmarc.us,mailto:a41f5123@forensics.dmarc-report.c",
      "om;ri=86400;fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=snip.ly",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 27 19:34:44 2026 GMT",
    "notAfter": "Nov 25 20:34:33 2026 GMT",
    "san": [
      "snip.ly",
      "*.snip.ly"
    ],
    "days_left": 60,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.20.47.26",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 302,
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
      "origin": "https://sub.snip.ly",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://snip.ly/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 302
  },
  "subdomains": {
    "source": "certspotter",
    "count": 10,
    "notable": [
      "app.snip.ly",
      "status.snip.ly",
      "support.snip.ly"
    ],
    "sample": [
      "app.snip.ly",
      "ctarendering.snip.ly",
      "failover.snip.ly",
      "prodcd.snip.ly",
      "snip.ly",
      "status.snip.ly",
      "support.snip.ly",
      "testingcd.snip.ly",
      "twitterbot.snip.ly",
      "verified.snip.ly"
    ]
  },
  "apex_txt": [
    "google-site-verification=E0-Y5g1NnmKsAykCJM_8ZcZ47F_kvKpiKqKBR8LAZjs",
    "stripe-verification=b8f011424d7440301c08c6a96b963dff0ea2b19d949b49b27948a371ed29",
    "google-site-verification=EMvnpww3LUyhGXCFgv6Dw6q-rTic9HE2PQYLq5MCz-4",
    "google-site-verification=Ff00bkXsoqs19-xOPGYHomnEZgewHP6MyNcSQxDOBNo",
    "google-site-verification=wr96MTDdDbqxCE3z7cewsOPGSCmGaVQC3z1qw4aooBk"
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
      "not_before": "20260827193444",
      "not_after": "20261125203433"
    }
  },
  "x12": {
    "status": 302
  },
  "elapsed_s": 11.2,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
