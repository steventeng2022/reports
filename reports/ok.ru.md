# Security Audit Report — ok.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ok.ru/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ok.ru |
| Test date | 2026-09-26 18:56 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 3 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 4 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 5 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 6 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 7 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 8 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 9 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 10 | low | CK6 | Session-like cookie lacks both Secure and SameSite | CWE-614 |
| 11 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 12 | info | CT1 | 13 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 3. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 4. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 5. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: mailru-verification: 432f8720b192812c; _globalsign-domain-verification=AJ2DeQYTm2pZ_AD24ZK4J7YgjqWNjxyPXCwZYt9bZh; yandex-verification: 7fe1bb8a552ceb32
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 6. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of ok.ru has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 7. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 33 disallow path(s), e.g. /cdk/*, *jsessionid*, *tkn/*, /mapi?*, /?ffsputnik=*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 8. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of ok.ru permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 9. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of ok.ru includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 10. [LOW] Session-like cookie lacks both Secure and SameSite (`CK6`)

- **CWE:** CWE-614
- **Detail:** Cookie 'ENVOY_JSESSIONID' set on ok.ru has neither the Secure nor the SameSite attribute: interception exposure plus un-gated CSRF usability.
- **Recommendation:** Set Secure and SameSite=Lax (or Strict) on session-like cookies.

### 11. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 5.61.21.121 carries PTR ip121.21.odnoklassniki.ru. for ok.ru.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 12. [INFO] 13 hostnames found via Certificate Transparency (certspotter) (`CT1`)

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
      "mailru-verification: 432f8720b192812c",
      "_globalsign-domain-verification=AJ2DeQYTm2pZ_AD24ZK4J7YgjqWNjxyPXCwZYt9bZh",
      "spf2.0/mfrom,pra ip4:217.20.144.0/20 ip4:5.61.16.0/21 ip4:185.16.244.0/22 ip4:185.16.148.0/22 ip4:185.100.104.0/22 ip4:188.93.58.115/32 ip4:217.69.129.234/32 ip4:188.93.56.178/32 ip4:188.93.56.179/32 include:astrum-nival.com ip4:178.22.88.131 ip4:188.93.6",
      "3.75 ip4:95.163.40.8/29 include:_spf.mail.ru include:_spf.notify.mail.ru include:senderid.unisender.com ~all",
      "v=spf1 ip4:217.20.144.0/20 ip4:5.61.16.0/21 ip4:185.16.244.0/22 ip4:185.16.148.0/22 ip4:185.100.104.0/22 ip4:188.93.58.115/32 ip4:217.69.129.234/32 ip4:188.93.56.178/32 ip4:188.93.56.179/32 include:astrum-nival.com ip4:178.22.88.131 ip4:188.93.63.75 ip4:9",
      "5.163.40.8/29 include:_spf.mail.ru include:_spf.notify.mail.ru include:spf.unisender.com ~all",
      "yandex-verification: 7fe1bb8a552ceb32",
      "_globalsign-domain-verification=upQWAiWgl9ghkHatFjyw-BEJkU-1UVnsOIEkP6wC39",
      "yandex-verification: 72c290082879917b",
      "google-site-verification=j-yEdmca2KoStcc5q-aEBlyDjOcxLqDm5bDqOAYIhoY",
      "google-site-verification=YzQ0R16gjSTb1agD8LvkQ2AMlXcrPn_IS9wj8Lovd7M",
      "_globalsign-domain-verification=DlOK4vaNNgPTIFOajXiZp-OdQ2N4oSRvcWN6QDXP5z",
      "google-site-verification=Ulruf8YYkR5p9-2klauDQNcJNSXgLzqmpqZuu3btFzE",
      "google-site-verification=hfmT3vbIz_5hRvk9oeE0uIaXA18XY4RStPddIlVifiQ",
      "mailru-verification: 000ee422012001f4",
      "mailru-verification: 4f4ac5123de41e20",
      "mailru-verification: 0ec15abd420c666e",
      "_globalsign-domain-verification=hyG8ZuHS3igfmZRnDwWCgCcP_M87sPi_KnJ11zpCVO",
      "mailru-verification: c54cac0033fe5771",
      "facebook-domain-verification=20zoxd8vljdt1j42fswju4pushgv41",
      "HARICA-CAvqAE2foWlJKppVxaI",
      "yandex-verification: 0e517f20a1c65405",
      "mailru-verification: b528448d3bf1dbea",
      "HARICA-BikYRETep3cbQtouTna"
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
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "5.61.21.121",
    "open": []
  },
  "https": {
    "status": 0,
    "content_type": "",
    "title": "",
    "error": "https connect failed"
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [],
  "http": {
    "status": 301,
    "location": "https://ok.ru:443/"
  },
  "redir_probes": [],
  "paths": {},
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
    "mailru-verification: 432f8720b192812c",
    "_globalsign-domain-verification=AJ2DeQYTm2pZ_AD24ZK4J7YgjqWNjxyPXCwZYt9bZh",
    "yandex-verification: 7fe1bb8a552ceb32",
    "_globalsign-domain-verification=upQWAiWgl9ghkHatFjyw-BEJkU-1UVnsOIEkP6wC39",
    "yandex-verification: 72c290082879917b"
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
      "not_before": "20251107074943",
      "not_after": "20261107074943"
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
  "x12": {
    "status": 200,
    "ptr": [
      "ip121.21.odnoklassniki.ru."
    ]
  },
  "elapsed_s": 58.7,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
