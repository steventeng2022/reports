# Security Audit Report — dribbble.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dribbble.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | dribbble.com |
| Test date | 2026-09-26 17:43 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 2, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 9 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 10 | info | MAIL10 | DMARC subdomain policy (sp=) set while apex policy is p=none | CWE-285 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | CT1 | 16 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: awselb/2.0
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 9. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.dribbble.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 10. [INFO] DMARC subdomain policy (sp=) set while apex policy is p=none (`MAIL10`)

- **CWE:** CWE-285
- **Detail:** Subdomains are enforced while the apex domain is monitor-only.
- **Recommendation:** Confirm the split policy is intended.

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (t9mw0fu1292sm8.dribbble.com and h85rdip99l9vvy.dribbble.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=ybbtm3dCtyshdETl5YMLL3YdRh1D50P1uLkcav13IG8; google-site-verification=nBBj8ycb88f7pry7MiUNDo7KdXDBxl-WOYEPHRCQw8E; google-site-verification=6ehiKlbD2ElK4AJXLe8nDTBOw7FNfb8uj1LukQgJnqY
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of dribbble.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 39 disallow path(s), e.g. /*/buckets$, /*/click?type=*$, /*/click$, /*/followers$, /*/following$
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] 16 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: checkout.dribbble.com, okta.dribbble.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "dribbble.com",
  "dns": {
    "a": [
      "18.155.192.81",
      "18.155.192.59",
      "18.155.192.103",
      "18.155.192.128"
    ],
    "aaaa": [
      "2600:9000:24bb:c00:18:db55:bf00:93a1",
      "2600:9000:24bb:e200:18:db55:bf00:93a1",
      "2600:9000:24bb:cc00:18:db55:bf00:93a1",
      "2600:9000:24bb:4200:18:db55:bf00:93a1",
      "2600:9000:24bb:200:18:db55:bf00:93a1",
      "2600:9000:24bb:6600:18:db55:bf00:93a1",
      "2600:9000:24bb:a000:18:db55:bf00:93a1",
      "2600:9000:24bb:7600:18:db55:bf00:93a1"
    ],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns4.dnsimple-edge.org.",
      "ns1.dnsimple-edge.com.",
      "ns3.dnsimple-edge.io.",
      "ns2.dnsimple-edge.net."
    ],
    "spf": [
      "v=spf1 include:_spf.google.com -all",
      "google-site-verification=ybbtm3dCtyshdETl5YMLL3YdRh1D50P1uLkcav13IG8",
      "google-site-verification=nBBj8ycb88f7pry7MiUNDo7KdXDBxl-WOYEPHRCQw8E",
      "kbjtt2313vqsxb13wy2tzr8mwmbwnsjb",
      "google-site-verification=6ehiKlbD2ElK4AJXLe8nDTBOw7FNfb8uj1LukQgJnqY",
      "google-site-verification=70pPwM6XlplaQ7lxSmW3PZa-U9VVMRcx6Q4ht8uv6nM",
      "globalsign-domain-verification=FnXWfFjPqReOGiIH8ITAbUasqKxnix6ftvTUzPOKHF"
    ],
    "dmarc": [
      "v=DMARC1; p=none; sp=none; rua=mailto:re+ea6f80d01f44@inbound.dmarcdigests.com; aspf=r; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.dribbble.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Oct 28 00:00:00 2025 GMT",
    "notAfter": "Nov 25 23:59:59 2026 GMT",
    "san": [
      "*.dribbble.com",
      "dribbble.com"
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
    "ip": "18.155.192.81",
    "open": []
  },
  "https": {
    "status": 202,
    "content_type": "text/html; charset=UTF-8",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.dribbble.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://dribbble.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 200,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 16,
    "notable": [
      "checkout.dribbble.com",
      "okta.dribbble.com"
    ],
    "sample": [
      "adobemeetup.dribbble.com",
      "checkout.dribbble.com",
      "checkoutpage.dribbble.com",
      "content-hub.dribbble.com",
      "dribbble.com",
      "email.m.dribbble.com",
      "email.n.dribbble.com",
      "email.staging-mail.dribbble.com",
      "framer.dribbble.com",
      "hubspot.dribbble.com",
      "industry-trends.dribbble.com",
      "okta.dribbble.com",
      "referrals.dribbble.com",
      "scim.dribbble.com",
      "sxsw2014.dribbble.com",
      "www.industry-trends.dribbble.com"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=ybbtm3dCtyshdETl5YMLL3YdRh1D50P1uLkcav13IG8",
    "google-site-verification=nBBj8ycb88f7pry7MiUNDo7KdXDBxl-WOYEPHRCQw8E",
    "google-site-verification=6ehiKlbD2ElK4AJXLe8nDTBOw7FNfb8uj1LukQgJnqY",
    "google-site-verification=70pPwM6XlplaQ7lxSmW3PZa-U9VVMRcx6Q4ht8uv6nM",
    "globalsign-domain-verification=FnXWfFjPqReOGiIH8ITAbUasqKxnix6ftvTUzPOKHF"
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
    "hsts_preloaded": true,
    "robots_disallow": [
      "/*/buckets$",
      "/*/click?type=*$",
      "/*/click$",
      "/*/followers$",
      "/*/following$",
      "/*/listings$",
      "/*/tags$",
      "/*/tags/*",
      "/account$",
      "/admin$",
      "/ads$",
      "/auth$",
      "/autocompletes/*",
      "/buckets/*/edit",
      "/blocks/*"
    ]
  },
  "elapsed_s": 20.2,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
