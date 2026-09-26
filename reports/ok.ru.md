# Security Audit Report — ok.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ok.ru/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ok.ru |
| Test date | 2026-09-26 17:50 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 3, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 8 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 9 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 10 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 11 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | CT1 | 13 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: envoy-lb7-prod; Java session cookie (J2EE)
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 5. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: envoy-lb7-prod
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'ENVOY_JSESSIONID' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 8. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'ENVOY_JSESSIONID' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 9. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie '_okAtTraceIds' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 10. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie '_okAtTraceIds' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

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

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=Ulruf8YYkR5p9-2klauDQNcJNSXgLzqmpqZuu3btFzE; mailru-verification: 432f8720b192812c; _globalsign-domain-verification=hyG8ZuHS3igfmZRnDwWCgCcP_M87sPi_KnJ11zpCVO
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of ok.ru has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 33 disallow path(s), e.g. /cdk/*, *jsessionid*, *tkn/*, /mapi?*, /?ffsputnik=*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] 13 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.ok.ru, test.ok.ru
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "ok.ru",
  "dns": {
    "a": [
      "5.61.21.121",
      "217.20.157.145"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxs.mail.ru (pref 10)"
    ],
    "ns": [
      "ns1.ok.ru.",
      "ns2.ok.ru.",
      "ns3.ok.ru."
    ],
    "spf": [
      "google-site-verification=Ulruf8YYkR5p9-2klauDQNcJNSXgLzqmpqZuu3btFzE",
      "mailru-verification: 432f8720b192812c",
      "_globalsign-domain-verification=hyG8ZuHS3igfmZRnDwWCgCcP_M87sPi_KnJ11zpCVO",
      "yandex-verification: 7fe1bb8a552ceb32",
      "HARICA-CAvqAE2foWlJKppVxaI",
      "mailru-verification: c54cac0033fe5771",
      "mailru-verification: b528448d3bf1dbea",
      "google-site-verification=j-yEdmca2KoStcc5q-aEBlyDjOcxLqDm5bDqOAYIhoY",
      "yandex-verification: 72c290082879917b",
      "spf2.0/mfrom,pra ip4:217.20.144.0/20 ip4:5.61.16.0/21 ip4:185.16.244.0/22 ip4:185.16.148.0/22 ip4:185.100.104.0/22 ip4:188.93.58.115/32 ip4:217.69.129.234/32 ip4:188.93.56.178/32 ip4:188.93.56.179/32 include:astrum-nival.com ip4:178.22.88.131 ip4:188.93.6",
      "3.75 ip4:95.163.40.8/29 include:_spf.mail.ru include:_spf.notify.mail.ru include:senderid.unisender.com ~all",
      "facebook-domain-verification=20zoxd8vljdt1j42fswju4pushgv41",
      "google-site-verification=YzQ0R16gjSTb1agD8LvkQ2AMlXcrPn_IS9wj8Lovd7M",
      "v=spf1 ip4:217.20.144.0/20 ip4:5.61.16.0/21 ip4:185.16.244.0/22 ip4:185.16.148.0/22 ip4:185.100.104.0/22 ip4:188.93.58.115/32 ip4:217.69.129.234/32 ip4:188.93.56.178/32 ip4:188.93.56.179/32 include:astrum-nival.com ip4:178.22.88.131 ip4:188.93.63.75 ip4:9",
      "5.163.40.8/29 include:_spf.mail.ru include:_spf.notify.mail.ru include:spf.unisender.com ~all",
      "_globalsign-domain-verification=AJ2DeQYTm2pZ_AD24ZK4J7YgjqWNjxyPXCwZYt9bZh",
      "_globalsign-domain-verification=upQWAiWgl9ghkHatFjyw-BEJkU-1UVnsOIEkP6wC39",
      "HARICA-BikYRETep3cbQtouTna",
      "_globalsign-domain-verification=DlOK4vaNNgPTIFOajXiZp-OdQ2N4oSRvcWN6QDXP5z",
      "mailru-verification: 0ec15abd420c666e",
      "google-site-verification=hfmT3vbIz_5hRvk9oeE0uIaXA18XY4RStPddIlVifiQ",
      "yandex-verification: 0e517f20a1c65405",
      "mailru-verification: 4f4ac5123de41e20",
      "mailru-verification: 000ee422012001f4"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;rua=mailto:dmarc_rua@corp.mail.ru;fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.ok.ru",
    "issuer": "countryName=GR, organizationName=Hellenic Academic and Research Institutions CA, commonName=HARICA DV TLS RSA",
    "notBefore": "Nov  7 07:49:43 2025 GMT",
    "notAfter": "Nov  7 07:49:43 2026 GMT",
    "san": [
      "*.ok.ru",
      "ok.ru",
      "m.odnoklassniki.am",
      "www.m.odnoklassniki.am",
      "m.odnoklasniki.by",
      "www.m.odnoklasniki.by",
      "*.oklive.app",
      "oklive.app",
      "*.odnoklassniki.ru",
      "odnoklassniki.ru",
      "*.tamtam.chat",
      "tamtam.chat",
      "m.odnoklasniki.ru",
      "www.m.odnoklasniki.ru",
      "*.okl.lt",
      "okl.lt",
      "m.odnoklassniki.co.ee",
      "www.m.odnoklassniki.co.ee",
      "*.mscu.ok.ru",
      "mscu.ok.ru",
      "*.dating.ok.ru",
      "dating.ok.ru",
      "m.odnoklassniki.by",
      "www.m.odnoklassniki.by",
      "m.odnoklasniki.ua",
      "www.m.odnoklasniki.ua",
      "*.ok.me",
      "ok.me",
      "m.odnoklassniki.eu",
      "www.m.odnoklassniki.eu",
      "m.odnoklassniki.lv",
      "www.m.odnoklassniki.lv",
      "*.tt.me",
      "tt.me",
      "*.m.odnoklassniki.ru",
      "m.odnoklassniki.ru",
      "m.odnoklassniki.tj",
      "www.m.odnoklassniki.tj",
      "*.ms.ok.ru",
      "ms.ok.ru",
      "*.m.ok.ru",
      "m.ok.ru"
    ],
    "days_left": 41,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "5.61.21.121",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html;charset=UTF-8",
    "title": "Социальная сеть Одноклассники. Общение с друзьями в ОК. Ваше место встречи с одноклассниками"
  },
  "mixed_content": [],
  "tech": [
    "Server: envoy-lb7-prod",
    "Java session cookie (J2EE)"
  ],
  "cookies": [
    {
      "domain": "ok.ru"
    },
    {
      "domain": "ok.ru"
    },
    {
      "domain": "ok.ru",
      "samesite": "none"
    },
    {},
    {},
    {}
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.ok.ru",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ok.ru:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 400
  },
  "subdomains": {
    "source": "certspotter",
    "count": 13,
    "notable": [
      "admin.ok.ru",
      "test.ok.ru"
    ],
    "sample": [
      "admin-test.ok.ru",
      "admin.ok.ru",
      "dating.ok.ru",
      "games-admin.ok.ru",
      "lab.ok.ru",
      "m.ok.ru",
      "ms.ok.ru",
      "mscu.ok.ru",
      "multitest.ok.ru",
      "ok.ru",
      "test.ok.ru",
      "test2.ok.ru",
      "test3.ok.ru"
    ]
  },
  "apex_txt": [
    "google-site-verification=Ulruf8YYkR5p9-2klauDQNcJNSXgLzqmpqZuu3btFzE",
    "mailru-verification: 432f8720b192812c",
    "_globalsign-domain-verification=hyG8ZuHS3igfmZRnDwWCgCcP_M87sPi_KnJ11zpCVO",
    "yandex-verification: 7fe1bb8a552ceb32",
    "mailru-verification: c54cac0033fe5771"
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
      "/cdk/*",
      "*jsessionid*",
      "*tkn/*",
      "/mapi?*",
      "/?ffsputnik=*",
      "/?_erv=*",
      "/?sputnik=*",
      "/?cat=*",
      "*st.redirect*",
      "*cmd=logExternal*",
      "*?fromTime=*",
      "*?cmd*",
      "/messages/join/*",
      "/joincall/*",
      "/gifts/link/*"
    ]
  },
  "elapsed_s": 39.9,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
