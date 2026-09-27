# Security Audit Report — zen.yandex.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://zen.yandex.ru/ |
| Bug bounty program | Yandex |
| Listed scope domain | zen.yandex.ru |
| Test date | 2026-09-27 02:49 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **25** (High: 0, Medium: 0, Low: 7, Info: 18)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | CK5 | Cookie scoped to parent domain (.yandex.ru) | CWE-200 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 19 | low | RD2 | HTTPS root redirects to a different domain | CWE-200 |
| 20 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 21 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 22 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |
| 23 | info | HTML14 | Public root document marked noindex | CWE-200 |
| 24 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 25 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

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

### 10. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://dzen.ru/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: mailru-verification: 74012169191518f4; yandex-verification: adcf799d964be8a8; facebook-domain-verification=3j25o2dnvau5xoluquutgkewnd2321
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] Cookie scoped to parent domain (.yandex.ru) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host zen.yandex.ru.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 91 disallow path(s), e.g. /about*?*, /away, /top$, /search, /money
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 87.250.254.116 carries PTR zen.yandex.net. for zen.yandex.ru.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 19. [LOW] HTTPS root redirects to a different domain (`RD2`)

- **CWE:** CWE-200
- **Detail:** https://zen.yandex.ru/ answered 302 with Location: https://dzen.ru/ (cross-domain handoff at the entry point).
- **Recommendation:** Review the cross-domain redirect; it discloses the real entry point and can be abused in open-redirect-style flows.

### 20. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for zen.yandex.ru; apex yandex.ru, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 21. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The zen.yandex.ru certificate lists an AIA OCSP responder (http://ocsp.globalsign.com/gsgccr46ovtlsca2025) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 22. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to zen.yandex.ru negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

### 23. [INFO] Public root document marked noindex (`HTML14`)

- **CWE:** CWE-200
- **Detail:** The root document of zen.yandex.ru is marked noindex (meta robots or X-Robots-Tag); a public homepage that is not indexable is a posture anomaly worth reviewing.
- **Recommendation:** Confirm the noindex directive is intentional.

### 24. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of zen.yandex.ru contains wildcard SAN entry(ies) *.zen.yandex.ru; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 25. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of zen.yandex.ru is http://ocsp.globalsign.com/gsgccr46ovtlsca2025; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

## Evidence (raw response observations)

```json
{
  "domain": "zen.yandex.ru",
  "dns": {
    "a": [
      "87.250.254.116"
    ],
    "aaaa": [
      "2a02:6b8::4fa"
    ],
    "cname": null,
    "mx": [
      "mx.yandex.ru (pref 10)"
    ],
    "ns": [
      "ns3.yandex.ru.",
      "ns4.yandex.ru."
    ],
    "caa": [],
    "spf": [
      "mailru-verification: 74012169191518f4",
      "v=spf1 include:_spf.yandex-team.ru include:mail.zendesk.com",
      "yandex-verification: adcf799d964be8a8",
      "facebook-domain-verification=3j25o2dnvau5xoluquutgkewnd2321",
      "google-site-verification=pS5x1twac3BzKk3hE85gZ3nDua-pdHnqwmamk-XtxP0",
      "google-site-verification=GuJk1T5z2NlhKlN-pHwdtqiFEFJmvjm4pDu-lbj4g5A"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "countryName=RU, stateOrProvinceName=Moscow, localityName=Moscow, organizationName=YANDEX LLC, commonName=*.zen.yandex.ru",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign GCC R46 OV TLS CA 2025",
    "notBefore": "Jul 27 21:14:09 2026 GMT",
    "notAfter": "Jan 25 20:59:59 2027 GMT",
    "san": [
      "*.zen.yandex.ru",
      "zen.yandex.com",
      "zen.yandex.uz",
      "zen.yandex.tm",
      "zen.yandex.tj",
      "zen.yandex.md",
      "zen.yandex.lv",
      "zen.yandex.lt",
      "zen.yandex.kz",
      "zen.yandex.kg",
      "zen.yandex.fr",
      "zen.yandex.ee",
      "zen.yandex.com.tr",
      "zen.yandex.com.ge",
      "zen.yandex.com.am",
      "zen.yandex.co.il",
      "zen.yandex.by",
      "zen.yandex.az",
      "zen.yandex",
      "zen.ya.ru",
      "yabro5.zen-test.yandex.ru",
      "yabro4.zen-test.yandex.ru",
      "yabro3.zen-test.yandex.ru",
      "yabro2.zen-test.yandex.ru",
      "yabro1.zen-test.yandex.ru",
      "www.zen.yandex.uz",
      "www.zen.yandex.tm",
      "www.zen.yandex.tj",
      "www.zen.yandex.md",
      "www.zen.yandex.lv",
      "www.zen.yandex.lt",
      "www.zen.yandex.kz",
      "www.zen.yandex.kg",
      "www.zen.yandex.fr",
      "www.zen.yandex.ee",
      "www.zen.yandex.com.tr",
      "www.zen.yandex.com.ge",
      "www.zen.yandex.com.am",
      "www.zen.yandex.co.il",
      "www.zen.yandex.by",
      "www.zen.yandex.az",
      "main.zdevx.yandex.ru",
      "dzen.yandex.ru",
      "dzen.ya.ru",
      "*.zen.yandex.com",
      "zen-redirect.yandex.ru",
      "zen.yandex.ru"
    ],
    "days_left": 120,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "87.250.254.116",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [
    {
      "domain": ".yandex.ru",
      "samesite": "none"
    },
    {
      "domain": ".yandex.ru",
      "samesite": "none"
    },
    {
      "domain": ".yandex.ru",
      "samesite": "none"
    },
    {
      "domain": ".yandex.ru",
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
      "origin": "https://sub.zen.yandex.ru",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://dzen.ru/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "mailru-verification: 74012169191518f4",
    "yandex-verification: adcf799d964be8a8",
    "facebook-domain-verification=3j25o2dnvau5xoluquutgkewnd2321",
    "google-site-verification=pS5x1twac3BzKk3hE85gZ3nDua-pdHnqwmamk-XtxP0",
    "google-site-verification=GuJk1T5z2NlhKlN-pHwdtqiFEFJmvjm4pDu-lbj4g5A"
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
      "aia_ocsp": "http://ocsp.globalsign.com/gsgccr46ovtlsca2025",
      "serial": 28998704483691655699238527808,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.globalsign.com/gsgccr46ovtlsca2025.crl"
      ],
      "san": [
        "*.zen.yandex.ru",
        "zen.yandex.com",
        "zen.yandex.uz",
        "zen.yandex.tm",
        "zen.yandex.tj",
        "zen.yandex.md",
        "zen.yandex.lv",
        "zen.yandex.lt",
        "zen.yandex.kz",
        "zen.yandex.kg",
        "zen.yandex.fr",
        "zen.yandex.ee",
        "zen.yandex.com.tr",
        "zen.yandex.com.ge",
        "zen.yandex.com.am",
        "zen.yandex.co.il",
        "zen.yandex.by",
        "zen.yandex.az",
        "zen.yandex",
        "zen.ya.ru"
      ],
      "subject_dn": "310b3009060355040613025255310f300d060355040813064d6f73636f77310f300d060355040713064d6f73636f7731133011060355040a130a59414e444558204c4c433118301606035504030c0f2a2e7a656e2e79616e6465782e7275",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312a302806035504031321476c6f62616c5369676e2047434320523436204f5620544c532043412032303235",
      "not_before": "20260727211409",
      "not_after": "20270125205959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/about*?*",
      "/away",
      "/top$",
      "/search",
      "/money",
      "/onboarding",
      "/news/top",
      "/news/smi",
      "/news/search",
      "/t/",
      "/user/",
      "/embed/",
      "/*/url",
      "/video/games/tags/",
      "/*sso_failed="
    ]
  },
  "x12": {
    "status": 302,
    "ptr": [
      "zen.yandex.net."
    ]
  },
  "x13": {
    "root_status": 302,
    "root_location": "https://dzen.ru/",
    "http_status": 302,
    "p404_status": 302,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 302,
    "crl": {
      "url": "http://crl.globalsign.com/gsgccr46ovtlsca2025.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "cipher_ver": "TLSv1.2",
    "root_status": 302
  },
  "x16": {
    "root_status": 302,
    "noindex": true
  },
  "x17": {
    "wildcard_san": [
      "*.zen.yandex.ru"
    ],
    "ocsp_http": "http://ocsp.globalsign.com/gsgccr46ovtlsca2025"
  },
  "elapsed_s": 71.1,
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
