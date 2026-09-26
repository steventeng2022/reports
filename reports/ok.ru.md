# Security Audit Report — ok.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ok.ru/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ok.ru |
| Test date | 2026-09-26 23:34 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **27** (High: 0, Medium: 0, Low: 5, Info: 22)

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
| 15 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 18 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 19 | low | CK6 | Session-like cookie lacks both Secure and SameSite | CWE-614 |
| 20 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 21 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 22 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 23 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 24 | info | HTML3 | Third-party <iframe> embedded in root document | CWE-643 |
| 25 | info | CK11 | Session-like cookie value has low entropy | CWE-340 |
| 26 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 27 | info | CT1 | 13 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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
- **Detail:** Apex TXT records with verification/token content: mailru-verification: 4f4ac5123de41e20; yandex-verification: 7fe1bb8a552ceb32; mailru-verification: c54cac0033fe5771
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.harica.gr -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 33 disallow path(s), e.g. /cdk/*, *jsessionid*, *tkn/*, /mapi?*, /?ffsputnik=*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of ok.ru permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 18. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of ok.ru includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 19. [LOW] Session-like cookie lacks both Secure and SameSite (`CK6`)

- **CWE:** CWE-614
- **Detail:** Cookie 'ENVOY_JSESSIONID' set on ok.ru has neither the Secure nor the SameSite attribute: interception exposure plus un-gated CSRF usability.
- **Recommendation:** Set Secure and SameSite=Lax (or Strict) on session-like cookies.

### 20. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 5.61.21.121 carries PTR ip121.21.odnoklassniki.ru. for ok.ru.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 21. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on ok.ru; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 22. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for ok.ru, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 23. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The ok.ru certificate lists an AIA OCSP responder (http://ocsp.harica.gr) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 24. [INFO] Third-party <iframe> embedded in root document (`HTML3`)

- **CWE:** CWE-643
- **Detail:** Root document of ok.ru embeds 1 cross-origin iframe(s), e.g. https://www.googletagmanager.com/ns.html?id=GTM-WFHQQ63; embedded origins are framed inside the page with its trust context.
- **Recommendation:** Review embedded origins and consider sandbox attributes.

### 25. [INFO] Session-like cookie value has low entropy (`CK11`)

- **CWE:** CWE-340
- **Detail:** Cookie 'ENVOY_JSESSIONID' on ok.ru is 18 chars with ~3.39 bits/char of entropy; low-entropy tokens are easier to guess.
- **Recommendation:** Generate session identifiers from a CSPRNG with sufficient entropy.

### 26. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on ok.ru is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 27. [INFO] 13 hostnames found via Certificate Transparency (certspotter) (`CT1`)

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
      "ns3.ok.ru.",
      "ns1.ok.ru.",
      "ns2.ok.ru."
    ],
    "caa": [],
    "spf": [
      "HARICA-CAvqAE2foWlJKppVxaI",
      "mailru-verification: 4f4ac5123de41e20",
      "yandex-verification: 7fe1bb8a552ceb32",
      "mailru-verification: c54cac0033fe5771",
      "google-site-verification=YzQ0R16gjSTb1agD8LvkQ2AMlXcrPn_IS9wj8Lovd7M",
      "google-site-verification=hfmT3vbIz_5hRvk9oeE0uIaXA18XY4RStPddIlVifiQ",
      "_globalsign-domain-verification=AJ2DeQYTm2pZ_AD24ZK4J7YgjqWNjxyPXCwZYt9bZh",
      "spf2.0/mfrom,pra ip4:217.20.144.0/20 ip4:5.61.16.0/21 ip4:185.16.244.0/22 ip4:185.16.148.0/22 ip4:185.100.104.0/22 ip4:188.93.58.115/32 ip4:217.69.129.234/32 ip4:188.93.56.178/32 ip4:188.93.56.179/32 include:astrum-nival.com ip4:178.22.88.131 ip4:188.93.6",
      "3.75 ip4:95.163.40.8/29 include:_spf.mail.ru include:_spf.notify.mail.ru include:senderid.unisender.com ~all",
      "google-site-verification=j-yEdmca2KoStcc5q-aEBlyDjOcxLqDm5bDqOAYIhoY",
      "mailru-verification: 432f8720b192812c",
      "_globalsign-domain-verification=hyG8ZuHS3igfmZRnDwWCgCcP_M87sPi_KnJ11zpCVO",
      "_globalsign-domain-verification=DlOK4vaNNgPTIFOajXiZp-OdQ2N4oSRvcWN6QDXP5z",
      "google-site-verification=Ulruf8YYkR5p9-2klauDQNcJNSXgLzqmpqZuu3btFzE",
      "mailru-verification: 0ec15abd420c666e",
      "facebook-domain-verification=20zoxd8vljdt1j42fswju4pushgv41",
      "yandex-verification: 0e517f20a1c65405",
      "mailru-verification: b528448d3bf1dbea",
      "yandex-verification: 72c290082879917b",
      "_globalsign-domain-verification=upQWAiWgl9ghkHatFjyw-BEJkU-1UVnsOIEkP6wC39",
      "v=spf1 ip4:217.20.144.0/20 ip4:5.61.16.0/21 ip4:185.16.244.0/22 ip4:185.16.148.0/22 ip4:185.100.104.0/22 ip4:188.93.58.115/32 ip4:217.69.129.234/32 ip4:188.93.56.178/32 ip4:188.93.56.179/32 include:astrum-nival.com ip4:178.22.88.131 ip4:188.93.63.75 ip4:9",
      "5.163.40.8/29 include:_spf.mail.ru include:_spf.notify.mail.ru include:spf.unisender.com ~all",
      "HARICA-BikYRETep3cbQtouTna",
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
    "mailru-verification: 4f4ac5123de41e20",
    "yandex-verification: 7fe1bb8a552ceb32",
    "mailru-verification: c54cac0033fe5771",
    "google-site-verification=YzQ0R16gjSTb1agD8LvkQ2AMlXcrPn_IS9wj8Lovd7M",
    "google-site-verification=hfmT3vbIz_5hRvk9oeE0uIaXA18XY4RStPddIlVifiQ"
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
      "aia_ocsp": "http://ocsp.harica.gr",
      "serial": 152576915679382943916837358952176900821,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.harica.gr/HARICA-DV-TLS-Sub-R1.crl"
      ],
      "subject_dn": "3110300e06035504030c072a2e6f6b2e7275",
      "issuer_dn": "310b300906035504061302475231373035060355040a0c2e48656c6c656e69632041636164656d696320616e6420526573656172636820496e737469747574696f6e73204341311a301806035504030c1148415249434120445620544c5320525341",
      "not_before": "20251107074943",
      "not_after": "20261107074943"
    },
    "ocsp": "http-403"
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
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=63072000;includeSubdomains;preload",
    "security_txt": "/.well-known/security.txt",
    "crl": {
      "url": "http://crl.harica.gr/HARICA-DV-TLS-Sub-R1.crl",
      "status": 200
    }
  },
  "elapsed_s": 53.6,
  "rechecked": "2026-09-26 23:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- Findings are reported against the public program scope; submission through the program tracker is pending.
