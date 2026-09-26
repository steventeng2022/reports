# Security Audit Report — pixiv.net

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pixiv.net/ |
| Bug bounty program | Pixiv |
| Listed scope domain | pixiv.net |
| Test date | 2026-09-26 17:51 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 3, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=xAnUeXKY_KgBIU3bipOPWHY9svivd1TqrjcW78IbVoI; globalsign-domain-verification=e_Nj1kv39zKi39YDMjczo6I7enPLWRCo7nMfs7uXGW; google-site-verification=oxtVRjNBArcXLAcQAnu4cMCqNrHIdNjRLdGE9yOsXOo
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of pixiv.net has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but pixiv.net is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 23 disallow path(s), e.g. /cdn-cgi/, /rpc/index.php?mode=profile_module_illusts&user_id=*&illust_id=*, /ajax/illust/*/recommend/init, *return_to*, /?return_to=
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "pixiv.net",
  "dns": {
    "a": [
      "210.140.139.158",
      "210.140.139.161",
      "210.140.139.152",
      "210.140.139.155"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns2.pixiv.net.",
      "ns1.pixiv.net."
    ],
    "spf": [
      "google-site-verification=xAnUeXKY_KgBIU3bipOPWHY9svivd1TqrjcW78IbVoI",
      "globalsign-domain-verification=e_Nj1kv39zKi39YDMjczo6I7enPLWRCo7nMfs7uXGW",
      "v=spf1 include:_spf.pixiv.net include:mail.zendesk.com include:sendgrid.net include:_spf.google.com ~all",
      "google-site-verification=oxtVRjNBArcXLAcQAnu4cMCqNrHIdNjRLdGE9yOsXOo",
      "facebook-domain-verification=ehppa9dvc6xcigimqv0ydnvdzl0kml",
      "OSSRH-78583",
      "google-site-verification=eVfT24dAtKUSNJTkjJKoEr4LOBLJyLfm3YN59oP5bRE",
      "google-site-verification=vNUz01aVidCrTTtKNCaiqUlfjOxCmVHRiuRQLTRq63A",
      "ca3-9373f91b0f6c49ee984a67d1e6325e4f",
      "firebase=pixiv-comic-store-production",
      "google-site-verification=rS1Mg2WHOuRkdwyS88Gfbm-Ol465if5TTLUL5h9lu-E"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:174afb3d51494e64bee7d0913aea39b2@dmarc-reports.cloudflare.net,mailto:dmarc@pixiv.com; ruf=mailto:dmarc@pixiv.com; fo=1:d:s"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-ECDSA-CHACHA20-POLY1305",
    "subject": "commonName=pixiv.net",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR1",
    "notBefore": "Aug  3 14:45:59 2026 GMT",
    "notAfter": "Nov  1 14:45:58 2026 GMT",
    "san": [
      "pixiv.net",
      "*.pixiv.net",
      "pixiv.me",
      "public-api.secure.pixiv.net",
      "oauth.secure.pixiv.net",
      "www.pixivision.net",
      "fanbox.cc",
      "*.fanbox.cc"
    ],
    "days_left": 35,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "210.140.139.158",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.pixiv.net",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.pixiv.net/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=xAnUeXKY_KgBIU3bipOPWHY9svivd1TqrjcW78IbVoI",
    "globalsign-domain-verification=e_Nj1kv39zKi39YDMjczo6I7enPLWRCo7nMfs7uXGW",
    "google-site-verification=oxtVRjNBArcXLAcQAnu4cMCqNrHIdNjRLdGE9yOsXOo",
    "facebook-domain-verification=ehppa9dvc6xcigimqv0ydnvdzl0kml",
    "google-site-verification=eVfT24dAtKUSNJTkjJKoEr4LOBLJyLfm3YN59oP5bRE"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/cdn-cgi/",
      "/rpc/index.php?mode=profile_module_illusts&user_id=*&illust_id=*",
      "/ajax/illust/*/recommend/init",
      "*return_to*",
      "/?return_to=",
      "/login.php?return_to=",
      "/index.php?return_to=",
      "/artworks/unlisted/*",
      "/users/*/followers",
      "/users/*/mypixiv",
      "/users/*/bookmarks",
      "/novel/comments.php?id=",
      "/novels/unlisted/*",
      "/en/group",
      "/en/search/"
    ]
  },
  "elapsed_s": 9.8,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
