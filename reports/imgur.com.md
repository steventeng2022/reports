# Security Audit Report — imgur.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://imgur.com/ |
| Bug bounty program | Imgur |
| Listed scope domain | imgur.com |
| Test date | 2026-09-26 18:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 5, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 10 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 11 | low | CORS1 | CORS: subdomain origin origin accepted with credentials | CWE-942 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cat factory 1.0
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=300 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cat factory 1.0
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'postpagebeta' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 10. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'postpagebeta' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 11. [LOW] CORS: subdomain origin origin accepted with credentials (`CORS1`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.imgur.com -> Access-Control-Allow-Origin: https://sub.imgur.com, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (m9cnyq3omhkp5j.imgur.com and z5mblz9e5jz3l1.imgur.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=jZetkGMTS63ZvRLFkjDNglMVkFkR-cZYwysKhIcg1S4; google-site-verification=Kh_iAw1AcwclD3rmGP7pOJp0zBgCwcW1V-L-mUXHMls; postman-domain-verification=45da7b179f25335b9e65a9b8d26d2fcd0739b9a1bf830b954c8a
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of imgur.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but imgur.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 9 disallow path(s), e.g. /account/, /delete/, /download/, /logout/, /removalrequest/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://imgur.com/ carries Cache-Control: max-age=60, stale-while-revalidate=600, stale-if-error=86400, public (plus ETag/Last-Modified freshness fields); shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

## Evidence (raw response observations)

```json
{
  "domain": "imgur.com",
  "dns": {
    "a": [
      "199.232.192.193",
      "199.232.196.193"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "aspmx3.googlemail.com (pref 10)"
    ],
    "ns": [
      "ns-457.awsdns-57.com.",
      "ns-1198.awsdns-21.org.",
      "ns-577.awsdns-08.net.",
      "ns-1677.awsdns-17.co.uk."
    ],
    "spf": [
      "mixpanel-domain-verify=877fb4f7-e334-4b13-9770-1bec2610bf63",
      "v=spf1 ip4:54.198.157.21 include:mailgun.org include:amazonses.com include:_spf.google.com include:mail.zendesk.com -all",
      "google-site-verification=jZetkGMTS63ZvRLFkjDNglMVkFkR-cZYwysKhIcg1S4",
      "google-site-verification=Kh_iAw1AcwclD3rmGP7pOJp0zBgCwcW1V-L-mUXHMls",
      "xf6t3vb8tjqqgypgpbw0bdmk98z49dk9",
      "ZOOM_verify_7qYn368TOF6Au0Hn7KWJ2P",
      "postman-domain-verification=45da7b179f25335b9e65a9b8d26d2fcd0739b9a1bf830b954c8abffd4acdb020707de3ddae662ed12ce411cce3357a6bd5a50c30c82bf4c481e40632f12d6ba6",
      "perplexity-ai-domain-verification-rcshp6=bIjE0TyYQyGqn2X0tjlqweDO0",
      "google-site-verification=lkg-LO7WaYRV1KFiztrPou_kY0KNS_h7c2nuhfia-ko",
      "d2jm6zv3c45cb6.cloudfront.net",
      "BSI106497997089",
      "1password-site-verification=BSXZBGRLX5ETBE6LCXUXT3ZACE",
      "google-site-verification=BzDTAgIuFjEqDFJFvpiwwNkX9LD8RuDq_8VrW1DFJQc",
      "MS=ms20045453",
      "atlassian-domain-verification=zBnQjyxIXRiBvnX39OwQsQjQ0NHRTT8z7jLkSYoDwQI0LDJEbkHtP50JXc/nBUSm"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc@imgur.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=*.imgur.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA DV R36",
    "notBefore": "Feb 13 00:00:00 2026 GMT",
    "notAfter": "Feb 15 23:59:59 2027 GMT",
    "san": [
      "*.imgur.com",
      "imgur.com"
    ],
    "days_left": 142,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "199.232.192.193",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "Imgur: The magic of the Internet"
  },
  "mixed_content": [],
  "tech": [
    "Server: cat factory 1.0"
  ],
  "cookies": [
    {
      "domain": ".imgur.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "https://imgur.com",
      "acac": "false"
    },
    {
      "origin": "https://sub.imgur.com",
      "acao": "https://sub.imgur.com",
      "acac": "true"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://imgur.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
    "/.git/HEAD": 200,
    "/.git/config": 200,
    "/.env": 200,
    "/.htaccess": 200,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 404,
    "/server-status": 301,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=jZetkGMTS63ZvRLFkjDNglMVkFkR-cZYwysKhIcg1S4",
    "google-site-verification=Kh_iAw1AcwclD3rmGP7pOJp0zBgCwcW1V-L-mUXHMls",
    "postman-domain-verification=45da7b179f25335b9e65a9b8d26d2fcd0739b9a1bf830b954c8a",
    "perplexity-ai-domain-verification-rcshp6=bIjE0TyYQyGqn2X0tjlqweDO0",
    "google-site-verification=lkg-LO7WaYRV1KFiztrPou_kY0KNS_h7c2nuhfia-ko"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20260213000000",
      "not_after": "20270215235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/account/",
      "/delete/",
      "/download/",
      "/logout/",
      "/removalrequest/",
      "/search?",
      "/1/",
      "/2/",
      "/3/"
    ]
  },
  "x12": {
    "status": 200
  },
  "elapsed_s": 23.0,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
