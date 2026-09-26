# Security Audit Report — dribbble.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dribbble.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | dribbble.com |
| Test date | 2026-09-26 22:03 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 2, Info: 18)

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
| 15 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 19 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 20 | info | CT1 | 16 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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
- **Detail:** Two random labels (yze8dbqnmx7mwn.dribbble.com and xln9446bs8chr5.dribbble.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=ybbtm3dCtyshdETl5YMLL3YdRh1D50P1uLkcav13IG8; globalsign-domain-verification=FnXWfFjPqReOGiIH8ITAbUasqKxnix6ftvTUzPOKHF; google-site-verification=70pPwM6XlplaQ7lxSmW3PZa-U9VVMRcx6Q4ht8uv6nM
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 39 disallow path(s), e.g. /*/buckets$, /*/click?type=*$, /*/click$, /*/followers$, /*/following$
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 18.67.110.54 carries PTR server-18-67-110-54.syd62.r.cloudfront.net. for dribbble.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkwvsgn8lrqoyq.html -> 404; error page/headers match: Nginx, CloudFront.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 19. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for dribbble.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 20. [INFO] 16 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: checkout.dribbble.com, okta.dribbble.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "dribbble.com",
  "dns": {
    "a": [
      "18.67.110.54",
      "18.67.110.100",
      "18.67.110.33",
      "18.67.110.49"
    ],
    "aaaa": [
      "2600:9000:2215:de00:18:db55:bf00:93a1",
      "2600:9000:2215:6a00:18:db55:bf00:93a1",
      "2600:9000:2215:bc00:18:db55:bf00:93a1",
      "2600:9000:2215:1400:18:db55:bf00:93a1",
      "2600:9000:2215:6c00:18:db55:bf00:93a1",
      "2600:9000:2215:d400:18:db55:bf00:93a1",
      "2600:9000:2215:4800:18:db55:bf00:93a1",
      "2600:9000:2215:2c00:18:db55:bf00:93a1"
    ],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx2.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns2.dnsimple-edge.net.",
      "ns3.dnsimple-edge.io.",
      "ns1.dnsimple-edge.com.",
      "ns4.dnsimple-edge.org."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=ybbtm3dCtyshdETl5YMLL3YdRh1D50P1uLkcav13IG8",
      "globalsign-domain-verification=FnXWfFjPqReOGiIH8ITAbUasqKxnix6ftvTUzPOKHF",
      "google-site-verification=70pPwM6XlplaQ7lxSmW3PZa-U9VVMRcx6Q4ht8uv6nM",
      "kbjtt2313vqsxb13wy2tzr8mwmbwnsjb",
      "google-site-verification=6ehiKlbD2ElK4AJXLe8nDTBOw7FNfb8uj1LukQgJnqY",
      "google-site-verification=nBBj8ycb88f7pry7MiUNDo7KdXDBxl-WOYEPHRCQw8E",
      "v=spf1 include:_spf.google.com -all"
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
    "ip": "18.67.110.54",
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
    "globalsign-domain-verification=FnXWfFjPqReOGiIH8ITAbUasqKxnix6ftvTUzPOKHF",
    "google-site-verification=70pPwM6XlplaQ7lxSmW3PZa-U9VVMRcx6Q4ht8uv6nM",
    "google-site-verification=6ehiKlbD2ElK4AJXLe8nDTBOw7FNfb8uj1LukQgJnqY",
    "google-site-verification=nBBj8ycb88f7pry7MiUNDo7KdXDBxl-WOYEPHRCQw8E"
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
      "aia_ocsp": "http://ocsp.r2m04.amazontrust.com",
      "not_before": "20251028000000",
      "not_after": "20261125235959"
    },
    "ocsp": "http-403"
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
  "x12": {
    "status": 202,
    "ptr": [
      "server-18-67-110-54.syd62.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 202,
    "http_status": 301,
    "p404_status": 404,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 22.7,
  "rechecked": "2026-09-26 21:56 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- Findings are reported against the public program scope; submission through the program tracker is pending.
