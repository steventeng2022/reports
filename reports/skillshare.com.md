# Security Audit Report — skillshare.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://skillshare.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | skillshare.com |
| Test date | 2026-09-27 02:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **25** (High: 0, Medium: 0, Low: 3, Info: 22)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 20 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 21 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 22 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 23 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |
| 24 | info | CT1 | 26 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 25 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.155.134:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.155.134:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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
- **Detail:** Header reveals: cloudflare
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=mcHpWbpzXVe4BOFgp5ijuXXqIf7OMoH1Z7ctm2mlBDc; jamf-site-verification=jsRO5e76-EWTHTbtESgo9g; h1-domain-verification=J1qQPbBWpbBxGVL3i3h1dpw2rX1NwHEZhnWeRNNP5L9qB2DX
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of skillshare.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 11 disallow path(s), e.g. /site/search/, /dashboard/, /reset-password/, /mixpanel/, /search?
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on skillshare.com indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for skillshare.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on skillshare.com lists 8 <loc> URL(s) across 9 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 20. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of skillshare.com carries alt-svc h3=":443"; ma=86400; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 21. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on skillshare.com identify the edge as CloudFront; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 22. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of skillshare.com contains wildcard SAN entry(ies) *.phoenix-demo.skillshare.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 23. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of skillshare.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

### 24. [INFO] 26 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: auth.skillshare.com, cloudflare.ingress.ops.skillshare.com, dev.skillshare.com, eng.ops.skillshare.com, events.docs.internal.skillshare.com, help.skillshare.com, ops.skillshare.com, prod.atlas.blog.skillshare.com, stg.atlas.blog.skillshare.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 25. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: dev.skillshare.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "skillshare.com",
  "dns": {
    "a": [
      "172.64.155.134",
      "104.18.32.122"
    ],
    "aaaa": [
      "2a06:98c1:310c::6812:207a",
      "2606:4700:440b::ac40:9b86"
    ],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 50)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)",
      "aspmx5.googlemail.com (pref 50)",
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx2.googlemail.com (pref 40)",
      "aspmx4.googlemail.com (pref 50)"
    ],
    "ns": [
      "ashe.skillshare.com.",
      "garen.skillshare.com."
    ],
    "caa": [],
    "spf": [
      "fw8mkvj2p2lgsk7crsrgylmvpzf0fkkw",
      "google-site-verification=mcHpWbpzXVe4BOFgp5ijuXXqIf7OMoH1Z7ctm2mlBDc",
      "9p1q7gjsjf6jgqmkdvbdxhxch33lxzsv",
      "amazonses:FA3mpwGhZzBmEIrp3iQXIXa3+umrH8ce03vBPry8tuI=",
      "jamf-site-verification=jsRO5e76-EWTHTbtESgo9g",
      "firebase=skillshare-creator-dev",
      "h1-domain-verification=J1qQPbBWpbBxGVL3i3h1dpw2rX1NwHEZhnWeRNNP5L9qB2DX",
      "mixpanel-domain-verify=739bd2fb-b682-4acf-9689-e94b74a61621",
      "atlassian-domain-verification=caa1SXVOa/jn5JVpUdP/OCpP1t9l1rz9ikhEsdPLJYGgYWquY6v2tDOvBhNoJG99",
      "apple-domain-verification=Hb38JzhNUvqf3hR2",
      "qyylpgj14chmtmds8wgz7j8lqwrd44tt",
      "google-site-verification=DshzQEv8w03dqk3NErt1hlkBaXsKdTMaUfBY1J-8Wic",
      "anthropic-domain-verification-0j2hh2=VDsV2bFDu3c0IZWFsXlG1WQ4h",
      "v=spf1 include:_spf0.skillshare.com include:_spf1.skillshare.com include:_spf2.skillshare.com include:_spf3.skillshare.com include:sendgrid.net include:_spf.google.com include:sendgrid.net include:_spf.google.com ip4:23.21.109.197 ip4:23.21.109.212 ~all",
      "facebook-domain-verification=va9wk46fanagqpr4rc6sp4d3gap007",
      "miro-verification=2accb01b1b638f37ee0cd64452e2faaa57e1cdf6",
      "openai-domain-verification=dv-98OuGQNGSB3R75FCYqMmzHqw"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:f4a1b21ad84d418380c0e4bd42294746@dmarc-reports.cloudflare.net; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=skillshare.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 19 16:07:16 2026 GMT",
    "notAfter": "Nov 17 17:07:13 2026 GMT",
    "san": [
      "skillshare.com",
      "phoenix-demo.skillshare.com",
      "*.phoenix-demo.skillshare.com"
    ],
    "days_left": 51,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.64.155.134",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "skillshare.com",
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
      "origin": "https://sub.skillshare.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://skillshare.com/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 26,
    "notable": [
      "auth.skillshare.com",
      "cloudflare.ingress.ops.skillshare.com",
      "dev.skillshare.com",
      "eng.ops.skillshare.com",
      "events.docs.internal.skillshare.com",
      "help.skillshare.com",
      "ops.skillshare.com",
      "prod.atlas.blog.skillshare.com",
      "stg.atlas.blog.skillshare.com"
    ],
    "sample": [
      "auth-development.skillshare.com",
      "auth-staging.skillshare.com",
      "auth-test.skillshare.com",
      "auth.skillshare.com",
      "blueshift-sandbox.skillshare.com",
      "brand.skillshare.com",
      "click.skillshare.com",
      "cloudflare.ingress.ops.skillshare.com",
      "design.skillshare.com",
      "dev.skillshare.com",
      "dreamjob.skillshare.com",
      "eng.ops.skillshare.com",
      "events.docs.internal.skillshare.com",
      "help.skillshare.com",
      "legal.skillshare.com",
      "ops.skillshare.com",
      "partners.skillshare.com",
      "phoenix-demo.skillshare.com",
      "preferences.skillshare.com",
      "prod.atlas.blog.skillshare.com"
    ],
    "dangling": [
      "dev.skillshare.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=mcHpWbpzXVe4BOFgp5ijuXXqIf7OMoH1Z7ctm2mlBDc",
    "jamf-site-verification=jsRO5e76-EWTHTbtESgo9g",
    "h1-domain-verification=J1qQPbBWpbBxGVL3i3h1dpw2rX1NwHEZhnWeRNNP5L9qB2DX",
    "atlassian-domain-verification=caa1SXVOa/jn5JVpUdP/OCpP1t9l1rz9ikhEsdPLJYGgYWquY6",
    "apple-domain-verification=Hb38JzhNUvqf3hR2"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "serial": 37871214768255014536102080016191288187,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/we1/6Xs4idXq35U.crl"
      ],
      "san": [
        "skillshare.com",
        "phoenix-demo.skillshare.com",
        "*.phoenix-demo.skillshare.com"
      ],
      "subject_dn": "311730150603550403130e736b696c6c73686172652e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531",
      "not_before": "20260819160716",
      "not_after": "20261117170713"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/site/search/",
      "/dashboard/",
      "/reset-password/",
      "/mixpanel/",
      "/search?",
      "/sessions/",
      "/checkout",
      "/reviews",
      "/cdn-cgi/",
      "/.well-known/",
      "/apple-app-site-association"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.skillshare.com/",
    "http_status": 301,
    "p404_status": 301,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=31536000; includeSubDomains; preload",
    "sitemap": {
      "urls": 8,
      "indexes": 9
    },
    "crl": {
      "url": "http://c.pki.goog/we1/6Xs4idXq35U.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "alt_svc": "h3=\":443\"; ma=86400",
    "cdn": [
      "CloudFront"
    ]
  },
  "x17": {
    "wildcard_san": [
      "*.phoenix-demo.skillshare.com"
    ]
  },
  "elapsed_s": 20.1,
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
