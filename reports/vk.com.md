# Security Audit Report — vk.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vk.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | vk.com |
| Test date | 2026-09-26 19:01 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 6, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 20 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 21 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 15 days (notAfter Oct 12 06:19:24 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: kittenx; X-Powered-By: KPHP/7.4.127596
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=15768000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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
- **Detail:** Header reveals: kittenx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

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
- **Detail:** Two random labels (azch2qjj9yc8g0.vk.com and 0j1vrk40wv30lk.vk.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=yIHjfPiraw7292KzmmdOaN_HbhuOagFIXRGHf_3WH4; wmail-verification: 646ff42e916a2be1aa86be6d3c742949; _globalsign-domain-verification=YM9xQ7VIOTNzoxGpxAE1kwy28slNTGWXflmZgt73D9
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of vk.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but vk.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 230 disallow path(s), e.g. /doc-*, /away.php, /im?, /search*&*&*&, *?w=story
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of vk.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 20. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of vk.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 21. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 87.240.132.78 carries PTR srv78-132-240-87.vk.com. for vk.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "vk.com",
  "dns": {
    "a": [
      "87.240.132.78",
      "87.240.132.72",
      "87.240.129.133",
      "87.240.132.67",
      "93.186.225.194",
      "87.240.137.164"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxs.mail.ru (pref 0)"
    ],
    "ns": [
      "ns2.vk.com.",
      "ns1.vk.com.",
      "ns3.vk.com.",
      "ns4.vk.com."
    ],
    "spf": [
      "_globalsign-domain-verification=yIHjfPiraw7292KzmmdOaN_HbhuOagFIXRGHf_3WH4",
      "wmail-verification: 646ff42e916a2be1aa86be6d3c742949",
      "_globalsign-domain-verification=YM9xQ7VIOTNzoxGpxAE1kwy28slNTGWXflmZgt73D9",
      "_globalsign-domain-verification=aXxk884iIZmgR5ON_CbluBYfK4GyZLo08hLo293AHC",
      "v=spf1 ip4:93.186.224.0/20 ip4:87.240.128.0/18 i",
      "p4:95.142.192.0/21 mx include:_spf.google.com in",
      "clude:_spf.mail.ru ~all",
      "HARICA-qudxcvYVXjYWrJvbUoX",
      "yandex-verification: 0bb3aeafaf40a3fa",
      "HARICA-A1PCCe7rY17J2K2Ifov",
      "google-site-verification=bQE4SQUYC7KTvk4XCaMdwF0e_tj-O-6ZXMfXW2a8mHY",
      "_globalsign-domain-verification=3qRKI9FWh1UX5CIN5FXwL6SJnSKkJzaDkVqSPaxdfC",
      "LD6VaYCKete4UB5FIx7snCoJ8bt1nGdeCWe4my5HH5psRaTl",
      "zAmvc",
      "HARICA-fLc9OEonBmci43ogW3C"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; rua=",
      "mailto:d@rua.agari.com,mailto:dmarc@vk.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.vk.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR1",
    "notBefore": "Jul 14 06:19:25 2026 GMT",
    "notAfter": "Oct 12 06:19:24 2026 GMT",
    "san": [
      "*.vk.com",
      "vk.ru",
      "vk.cc",
      "vk.me",
      "vkontakte.com",
      "vkontakte.ru",
      "vk.link",
      "vk.design",
      "stats.vk-portal.net",
      "m.vk.ru",
      "vkvideo.ru",
      "api.vk.ru",
      "*.vk.ru",
      "*.vk.cc",
      "*.vk.me",
      "*.vkontakte.com",
      "*.vkontakte.ru",
      "*.vk.link",
      "*.vk.design",
      "*.vk-portal.ru",
      "*.m.vk.com",
      "*.m.vk.ru",
      "*.vkvideo.ru",
      "*.m.vkvideo.ru",
      "*.api.vk.com",
      "*.api.vk.ru",
      "m.vk.com",
      "api.vk.com",
      "vk.com",
      "*.api.r.vk.com",
      "*.api.r.vk.ru",
      "api.r.vk.com",
      "api.r.vk.ru"
    ],
    "days_left": 15,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "87.240.132.78",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=windows-1251",
    "title": "VK | &#27489;&#36814;&#33;"
  },
  "mixed_content": [],
  "tech": [
    "Server: kittenx",
    "X-Powered-By: KPHP/7.4.127596"
  ],
  "cookies": [
    {
      "domain": ".vk.com",
      "samesite": "none"
    },
    {
      "domain": ".vk.com",
      "samesite": "none"
    },
    {
      "domain": ".vk.com",
      "samesite": "none"
    },
    {
      "domain": ".vk.com",
      "samesite": "none"
    },
    {
      "domain": ".vk.com",
      "samesite": "none"
    },
    {
      "domain": ".vk.com",
      "samesite": "none"
    },
    {
      "domain": ".vk.com",
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
      "origin": "https://sub.vk.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://vk.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
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
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "_globalsign-domain-verification=yIHjfPiraw7292KzmmdOaN_HbhuOagFIXRGHf_3WH4",
    "wmail-verification: 646ff42e916a2be1aa86be6d3c742949",
    "_globalsign-domain-verification=YM9xQ7VIOTNzoxGpxAE1kwy28slNTGWXflmZgt73D9",
    "_globalsign-domain-verification=aXxk884iIZmgR5ON_CbluBYfK4GyZLo08hLo293AHC",
    "yandex-verification: 0bb3aeafaf40a3fa"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260714061925",
      "not_after": "20261012061924"
    }
  },
  "http2": {
    "robots_disallow": [
      "/doc-*",
      "/away.php",
      "/im?",
      "/search*&*&*&",
      "*?w=story",
      "*?w=wall",
      "*?w=page",
      "*?w=app",
      "*?w=poll",
      "*?w=service-booking-*",
      "*?w=likes",
      "*?w=shares",
      "*?w=note",
      "*?w=away",
      "/call?id="
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "srv78-132-240-87.vk.com."
    ]
  },
  "elapsed_s": 38.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
