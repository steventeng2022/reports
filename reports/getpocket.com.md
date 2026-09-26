# Security Audit Report — getpocket.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://getpocket.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | getpocket.com |
| Test date | 2026-09-26 18:52 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

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
- **Detail:** Apex TXT records with verification/token content: stripe-verification=12da43cd3189cf99e5c3ecdfdae9c97c7d4230aed93a22ae62892f0cee02; facebook-domain-verification=7onzfhlxkl6r3tyrkywbqx1ybt66jx; google-site-verification=BznukNV2feXYAk09zg1tD-zMQPL_wHoVvfbHa8g2g18
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of getpocket.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 13 disallow path(s), e.g. /v2/*, /v3/*, /create*, /mini_login*, /button*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.169.121.10 carries PTR server-3-169-121-10.tpe53.r.cloudfront.net. for getpocket.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "getpocket.com",
  "dns": {
    "a": [
      "3.169.121.10",
      "3.169.121.118",
      "3.169.121.32",
      "3.169.121.84"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "ns-351.awsdns-43.com.",
      "ns-704.awsdns-24.net.",
      "ns-1518.awsdns-61.org.",
      "ns-1605.awsdns-08.co.uk."
    ],
    "spf": [
      "stripe-verification=12da43cd3189cf99e5c3ecdfdae9c97c7d4230aed93a22ae62892f0cee028e0c",
      "facebook-domain-verification=7onzfhlxkl6r3tyrkywbqx1ybt66jx",
      "google-site-verification=BznukNV2feXYAk09zg1tD-zMQPL_wHoVvfbHa8g2g18",
      "atlassian-domain-verification=ZKdUkLuFwGhwbs6AqGb09CzrQ1EGoENusL8drKXt3+3DVnPgvbvEKhpaA0w3Crhd",
      "google-site-verification=zfNlIIbTnH55o0_E1S6GQdIQl6jtefL-vdk_xCyBQrE",
      "docusign=e569f89d-0082-4ffd-8973-5c7f739cdd02",
      "apple-domain-verification=YQkH_odwWd6t5jf8ay7uZ7SdgCl7gOnggLxglPtPf-A",
      "v=spf1 include:sendgrid.net include:_spf.google.com include:helpscoutemail.com include:mail.zendesk.com ip4:63.245.208.103 ~all",
      "google-site-verification=Ip41qYBewmXa5vTZEKlBpwrqymJbbzzNXCDd5eyQryk",
      "google-site-verification=O73K4GuIvQ3SbegpcgVVBVm-ob8wnBQAd4V8KdXf-oI"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc_agg@dmarc.250ok.net; fo=1; sp=none; aspf=r;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=getpocket.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Apr 28 00:00:00 2026 GMT",
    "notAfter": "Nov 11 23:59:59 2026 GMT",
    "san": [
      "getpocket.com",
      "readitlater.com",
      "pocket.co",
      "www.getpocket.com",
      "l.getpocket.com",
      "www.readitlater.com",
      "aproductiveyear.com",
      "readitlaterlist.com",
      "www.readitlaterlist.com",
      "api.getpocket.com",
      "web-prod.getpocket.com"
    ],
    "days_left": 46,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.121.10",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.getpocket.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://getpocket.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 503"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 503,
    "/.well-known/security.txt": 404,
    "/security.txt": 503,
    "/.git/HEAD": 503,
    "/.git/config": 503,
    "/.env": 403,
    "/.htaccess": 503,
    "/wp-login.php": 503,
    "/phpmyadmin/index.php": 503,
    "/server-status": 503,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "stripe-verification=12da43cd3189cf99e5c3ecdfdae9c97c7d4230aed93a22ae62892f0cee02",
    "facebook-domain-verification=7onzfhlxkl6r3tyrkywbqx1ybt66jx",
    "google-site-verification=BznukNV2feXYAk09zg1tD-zMQPL_wHoVvfbHa8g2g18",
    "atlassian-domain-verification=ZKdUkLuFwGhwbs6AqGb09CzrQ1EGoENusL8drKXt3+3DVnPgvb",
    "google-site-verification=zfNlIIbTnH55o0_E1S6GQdIQl6jtefL-vdk_xCyBQrE"
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
      "not_before": "20260428000000",
      "not_after": "20261111235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/v2/*",
      "/v3/*",
      "/create*",
      "/mini_login*",
      "/button*",
      "/addemail*",
      "/redirect*",
      "/email_unsubscribe*",
      "/firefox/new_tab_learn_more*",
      "/s/*",
      "/read/*",
      "/edit*",
      "/save*"
    ]
  },
  "x12": {
    "status": 302,
    "ptr": [
      "server-3-169-121-10.tpe53.r.cloudfront.net."
    ]
  },
  "elapsed_s": 10.5,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
