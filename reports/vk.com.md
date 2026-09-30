# Security Audit Report — vk.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vk.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | vk.com |
| Test date | 2026-09-27 02:48 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **29** (High: 0, Medium: 0, Low: 8, Info: 21)

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
| 21 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 22 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 23 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 24 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 25 | info | H25 | server-timing response header exposed | CWE-200 |
| 26 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 27 | info | HTML16 | Inline event handlers in root document | CWE-79 |
| 28 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 29 | low | S1 | First-party branded subdomain surface (live status origin, mail handoff, catch-all) (not dangling) | CWE-916 |

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
- **Detail:** Two random labels (sb5n02sesjllb8.vk.com and rpc8gffh9z94vg.vk.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=aXxk884iIZmgR5ON_CbluBYfK4GyZLo08hLo293AHC; _globalsign-domain-verification=3qRKI9FWh1UX5CIN5FXwL6SJnSKkJzaDkVqSPaxdfC; _globalsign-domain-verification=yIHjfPiraw7292KzmmdOaN_HbhuOagFIXRGHf_3WH4
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

### 21. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on vk.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 22. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for vk.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 23. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of vk.com loads 38 cross-origin script(s) without an integrity attribute, e.g. https://st1-55.vk.ru/dist/core_spa/error_monitoring.isolated.dbe0b86e.js, https://st1-55.vk.ru/dist/core_spa/core_spa_vk.dbc76b49.js, https://st1-55.vk.ru/dist/web/chunks/vkcom-kit.b006b9f9.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 24. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of vk.com sends a CSP but contains 13 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 25. [INFO] server-timing response header exposed (`H25`)

- **CWE:** CWE-200
- **Detail:** The root response of vk.com sends server-timing (tid;desc="5WIxQw6mSvPW5tfVrsJHFj8NlQ8hTw",front;dur=456.831); server/edge processing metrics are disclosed to any client.
- **Recommendation:** Restrict server-timing to authenticated/debug contexts if the internals are sensitive.

### 26. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of vk.com contains wildcard SAN entry(ies) *.vk.com, *.vk.ru, *.vk.cc; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 27. [INFO] Inline event handlers in root document (`HTML16`)

- **CWE:** CWE-79
- **Detail:** The root document of vk.com contains 20 inline event handler attribute(s); each is a DOM-level execution point that SRI does not constrain.
- **Recommendation:** Move handlers to external scripts where feasible and keep them covered by CSP.
### 28. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** GET /?ch=Zx7qK2v9Bm (200, 182,320 B) reflects the token inside an inline <script> JSON blob (params.loc at index 176989); /?id= behaves the same. Quote-breakout probes (" and ') are re-encoded to %22/%27 (token index -1) and CRLF/LF probes are re-encoded, so no script or attribute breakout was observed (probe-r35vk, probe-r35c-vk).
- **Recommendation:** Treat the reflected challenge parameter as untrusted data; keep strict JSON/URL encoding on every render path.

### 29. [LOW] First-party branded subdomain surface (live status origin, mail handoff, catch-all) (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** status.vk.com = 200 (2 B "ok", kittenx origin, first-party); mail.vk.com = 302 -> vk.mail.ru; admin/app.vk.com = 403 (550 B first-party); mx/smtp.vk.com = 403 (564 B nginx); ~20 other probed subdomains 301 -> vk.com/ catch-all. No 915 B dangling CloudFront 403 signature found (probe-r35e-subs).
- **Recommendation:** Keep the status origin first-party; prune or claim catch-all subdomains.

## Active re-verification (2026-09-30, agent-aggressive)

- **I1 x1:** /?ch= and /?id= re-probed with token Zx7qK2v9Bm = 200 (182,320 B); token only in inline <script> JSON (params.loc); " and ' probes -> %22/%27 with tokenIdx=-1, no breakout (probe-r35vk, probe-r35c-vk).
- **S1 x1:** status = 200 "ok" (kittenx), mail 302 -> vk.mail.ru, admin/app 403 (550 B), mx/smtp 403 (564 B nginx), ~20 subs 301 -> vk.com/ catch-all; no 915 B dangling CloudFront signature (probe-r35e-subs).

## Evidence (raw response observations)

```json
{
  "domain": "vk.com",
  "dns": {
    "a": [
      "93.186.225.194",
      "87.240.132.72",
      "87.240.132.67",
      "87.240.132.78",
      "87.240.129.133",
      "87.240.137.164"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxs.mail.ru (pref 0)"
    ],
    "ns": [
      "ns3.vk.com.",
      "ns2.vk.com.",
      "ns1.vk.com.",
      "ns4.vk.com."
    ],
    "caa": [],
    "spf": [
      "HARICA-qudxcvYVXjYWrJvbUoX",
      "HARICA-A1PCCe7rY17J2K2Ifov",
      "HARICA-fLc9OEonBmci43ogW3C",
      "_globalsign-domain-verification=aXxk884iIZmgR5ON_CbluBYfK4GyZLo08hLo293AHC",
      "_globalsign-domain-verification=3qRKI9FWh1UX5CIN5FXwL6SJnSKkJzaDkVqSPaxdfC",
      "_globalsign-domain-verification=yIHjfPiraw7292KzmmdOaN_HbhuOagFIXRGHf_3WH4",
      "_globalsign-domain-verification=YM9xQ7VIOTNzoxGpxAE1kwy28slNTGWXflmZgt73D9",
      "wmail-verification: 646ff42e916a2be1aa86be6d3c742949",
      "google-site-verification=bQE4SQUYC7KTvk4XCaMdwF0e_tj-O-6ZXMfXW2a8mHY",
      "yandex-verification: 0bb3aeafaf40a3fa",
      "LD6VaYCKete4UB5FIx7snCoJ8bt1nGdeCWe4my5HH5psRaTl",
      "zAmvc",
      "v=spf1 ip4:93.186.224.0/20 ip4:87.240.128.0/18 i",
      "p4:95.142.192.0/21 mx include:_spf.google.com in",
      "clude:_spf.mail.ru ~all"
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
    "ip": "93.186.225.194",
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
    "_globalsign-domain-verification=aXxk884iIZmgR5ON_CbluBYfK4GyZLo08hLo293AHC",
    "_globalsign-domain-verification=3qRKI9FWh1UX5CIN5FXwL6SJnSKkJzaDkVqSPaxdfC",
    "_globalsign-domain-verification=yIHjfPiraw7292KzmmdOaN_HbhuOagFIXRGHf_3WH4",
    "_globalsign-domain-verification=YM9xQ7VIOTNzoxGpxAE1kwy28slNTGWXflmZgt73D9",
    "wmail-verification: 646ff42e916a2be1aa86be6d3c742949"
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
      "serial": 95829498625717538324955658188383539498,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/wr1/ehmxk4X0Mqk.crl"
      ],
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
        "*.vk-portal.ru"
      ],
      "subject_dn": "3111300f06035504030c082a2e766b2e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303575231",
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
    "status": 200
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
      "/.well-known/assetlinks.json"
    ],
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=15768000",
    "crl": {
      "url": "http://c.pki.goog/wr1/ehmxk4X0Mqk.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "x16": {
    "root_status": 200,
    "server_timing": "tid;desc=\"5WIxQw6mSvPW5tfVrsJHFj8NlQ8hTw\",front;dur=456.831"
  },
  "x17": {
    "wildcard_san": [
      "*.vk.com",
      "*.vk.ru",
      "*.vk.cc",
      "*.vk.me",
      "*.vkontakte.com"
    ],
    "inline_handlers": 20
  },
  "elapsed_s": 54.0,
  "rechecked": "2026-09-27 02:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- re-run #15 passive additions: TLS 1.0/1.1, cipher-suite and key-exchange observations come from the handshake the base TLS check already performed plus one quiet re-handshake with no HTTP traffic; HTML-level angles read the root document already fetched for header checks; the only extra request this pass is a read-only GET to /.well-known/openid-configuration (plus the earlier passes' security.txt, sitemap.xml and CRL GETs).
- re-run #16 passive additions: the edge/protocol angles read the alt-svc, server-timing and CDN-identification headers from the one root GET; the preconnect/dns-prefetch, base-href and noindex angles parse the already-fetched root document; the TLS 1.2-only ceiling, SHA-1 signature and weak-key angles use the certificate evidence the base TLS check already captured; the only extra requests this pass are two read-only GETs (/.well-known/jwks.json and /.well-known/change-password).
- re-run #17 passive additions: the retired-header angles (Public-Key-Pins, Expect-CT, X-Permitted-Cross-Domain-Policies, Via, COOP/COEP, Permissions-Policy) read from the one root GET; the wildcard SAN, http:// OCSP and 398-day-cap angles use the certificate evidence the base TLS check already captured (SAN now harvested from the existing DER); the only extra requests this pass are three read-only GETs (/.well-known/dpop-jwks.json, /.well-known/origin-rsa-keys.json, /.well-known/llms.txt).
- Findings are reported against the public program scope; submission through the program tracker is pending.
