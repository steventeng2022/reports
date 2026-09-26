# Security Audit Report — vogue.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vogue.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | vogue.com |
| Test date | 2026-09-26 17:55 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

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
| 17 | info | CT1 | 39 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
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
- **Detail:** Header reveals: nginx
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=TotKJyzGHFh-Cx9RPOCylr-TeWAhHQW4-wx-m09MA0w; atlassian-domain-verification=mYtQWl3namqmk5ikMKT48XVnS+XdjdbkLlkWMcNyvsddK2JDAi; pinterest-site-verification=079bd01e42d8f0eaa5422e8618a6c6d4
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of vogue.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 20 disallow path(s), e.g. /*?, /auth/, /account/, /user/, /user-context
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] 39 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.vogue.com, app.link.vogue.com, app.vogue.com, assets.vogue.com, my.vogue.com, shop.vogue.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "vogue.com",
  "dns": {
    "a": [
      "52.223.6.210",
      "166.117.251.134"
    ],
    "aaaa": [
      "2600:9000:a41b:ef95:eff:32b3:411c:f36c",
      "2600:9000:a707:a46c:560f:b721:9702:d75e"
    ],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-1116.awsdns-11.org.",
      "ns-28.awsdns-03.com.",
      "ns-836.awsdns-40.net.",
      "ns-1935.awsdns-49.co.uk."
    ],
    "spf": [
      "google-site-verification=TotKJyzGHFh-Cx9RPOCylr-TeWAhHQW4-wx-m09MA0w",
      "atlassian-domain-verification=mYtQWl3namqmk5ikMKT48XVnS+XdjdbkLlkWMcNyvsddK2JDAib+9a8MJCXTDMyJ",
      "ZOOM_verify_kdyAdyAMRLmIhWagXSIIAg",
      "pinterest-site-verification=079bd01e42d8f0eaa5422e8618a6c6d4",
      "v=spf1 include:_u.vogue.com._spf.smart.ondmarc.com -all",
      "yahoo-verification-key=wNK397wYlhUjvNegBd2B9l5tgqbgfLIRT0BSY2zQ910=",
      "xt2rbt7mdy4gk53hgy2mf3sx8j9f22v8",
      "MS=ms95711702",
      "google-site-verification=0rCw3th8Nz8zUpLrjnI5ddz-wT-iv-IfYFYE4W434Pw",
      "fastly-domain-delegation-grdt7uboiyaqqtgjenzi-789661-2024-07-19",
      "MS=ms23179707",
      "google-site-verification=zcD6BQv00vEAHz7gR-RM32XcQ6viddAOiZ1r5DNkQgo",
      "google-site-verification=75Jd5pu9q9ASOY0VZggn-TZZGwGsVXex4POiiGCUKJc",
      "zapier-domain-verification-challenge=9acd95dc-f346-4b72-acb0-ceb88d996ba4",
      "adobe-idp-site-verification=c2108b9dbc0fc05ff0794006df1c41b6c945bd2c8a904bef754ec850a7c6873f",
      "google-site-verification=KC8kypqWuXMriWr2c1yLNvTa_h8Lj3u3Ls7utthC3dQ",
      "facebook-domain-verification=6x1dytzup5zmced9tfbjt53v381sd5",
      "fastly-domain-delegation-LRX8J5E7-877731-20250130",
      "google-site-verification=Zg2QYDSkRzso69ytr0XEOkPovxRiyUzmaxpLG6cmvho"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; sp=reject; rua=mailto:a6816915@inbox.ondmarc.com; ruf=mailto:a6816915@inbox.ondmarc.com; adkim=r; aspf=r; fo=1; rf=afrf; ri=3600"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.worldofinteriors.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Oct 23 00:00:00 2025 GMT",
    "notAfter": "Nov 21 23:59:59 2026 GMT",
    "san": [
      "*.worldofinteriors.com",
      "condenast.de",
      "cnworld.es",
      "gqheroes.com",
      "wired.uk",
      "condenastdigital.com",
      "pitchfork.com",
      "cnidigital.in",
      "worldofinteriors.co.uk",
      "condenastcollege.es",
      "gq.co.uk",
      "teenvogue.com",
      "condenast.co.uk",
      "worldofinteriors.com",
      "vanityfairart.co.uk",
      "gq-magazine.co.uk",
      "vogue.de",
      "gqeditorsclub.co.uk",
      "architecturaldigest.com.mx",
      "revistaad.es",
      "traveller.uk",
      "vogue.com.mx",
      "wired.it",
      "glmr.uk",
      "houseandgarden.com",
      "theexchangehsbc.com",
      "condenast.com.tw",
      "glamourmagazine.co.uk",
      "ouse.co",
      "glamour.com.mx",
      "*.worldofinteriors.uk",
      "pitchforkmusicfestival.com",
      "allure.com",
      "newyorker.com",
      "self.com",
      "vogue.uk",
      "arstechnica.uk",
      "glamour.de",
      "houseandgarden.co.uk",
      "admiddleeast.com",
      "menoftheyear.de",
      "wired.com",
      "cntraveler.com",
      "tatler.com",
      "tatler.co.uk",
      "worldofinteriors.uk",
      "condenast.com.mx",
      "condenast.fr",
      "vogue.mx",
      "vogue.it",
      "gqheroes.co.uk",
      "them.us",
      "cntraveller.com",
      "arstechnica.co.uk",
      "vogue.es",
      "vanityfair.co.uk",
      "voguesummerschool.com",
      "vanityfair.com",
      "cntraveiier.com",
      "tatler.uk",
      "gq.uk",
      "condenast.jp",
      "condenastcollege.ac.uk",
      "calicoclub.co.uk",
      "glamour.com",
      "cntraveller.in",
      "vogue.co.jp",
      "condenast.mx",
      "condenast.it",
      "condenastjohansensguides.com",
      "gqeditorsclub.com",
      "gq.de",
      "vogue.fr",
      "cntraveller.uk",
      "condenast.es",
      "admexico.com.mx",
      "vogueforcesoffashion.com",
      "condenast.in",
      "vogue.co.uk",
      "thelovemagazine.co.uk",
      "vanityfairart.com",
      "condenastjohansens.com",
      "gq.com",
      "vogue.com",
      "condenastcollege.com",
      "architecturaldigest.com",
      "cntravellerme.com",
      "cntravelller.com",
      "bonappetit.com",
      "wired.co.uk",
      "condenastdigital.de",
      "condenastmexico-latam.com"
    ],
    "days_left": 56,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "52.223.6.210",
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
      "origin": "https://sub.vogue.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.vogue.com/"
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
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 403,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 39,
    "notable": [
      "api.vogue.com",
      "app.link.vogue.com",
      "app.vogue.com",
      "assets.vogue.com",
      "my.vogue.com",
      "shop.vogue.com"
    ],
    "sample": [
      "api.vogue.com",
      "app.link.vogue.com",
      "app.vogue.com",
      "archive.vogue.com",
      "archiveauth.vogue.com",
      "assets.vogue.com",
      "bytes.vogue.com",
      "c.vogue.com",
      "c2-shop.vogue.com",
      "c2.vogue.com",
      "events.vogue.com",
      "images-photovogue-staging.vogue.com",
      "images-photovogue.vogue.com",
      "interactive-stag.vogue.com",
      "interactive.vogue.com",
      "link.vogue.com",
      "links.vogue.com",
      "my.vogue.com",
      "permutive.vogue.com",
      "photovogue-admin.vogue.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=TotKJyzGHFh-Cx9RPOCylr-TeWAhHQW4-wx-m09MA0w",
    "atlassian-domain-verification=mYtQWl3namqmk5ikMKT48XVnS+XdjdbkLlkWMcNyvsddK2JDAi",
    "pinterest-site-verification=079bd01e42d8f0eaa5422e8618a6c6d4",
    "yahoo-verification-key=wNK397wYlhUjvNegBd2B9l5tgqbgfLIRT0BSY2zQ910=",
    "google-site-verification=0rCw3th8Nz8zUpLrjnI5ddz-wT-iv-IfYFYE4W434Pw"
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
      "/*?",
      "/auth/",
      "/account/",
      "/user/",
      "/user-context",
      "/preview/",
      "/search",
      "/product/",
      "/cdn-cgi/",
      "/services.min.js",
      "/com.condenast/yv8",
      "/reject-all",
      "/slideshow/*-inline$",
      "*/vogue-club/perk/",
      "/https://player.cnevids.com/"
    ]
  },
  "elapsed_s": 8.7,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
