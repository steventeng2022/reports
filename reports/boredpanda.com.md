# Security Audit Report — boredpanda.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://boredpanda.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | boredpanda.com |
| Test date | 2026-09-27 02:20 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **26** (High: 0, Medium: 0, Low: 6, Info: 20)

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
| 11 | low | RED7 | HTTPS root redirects to plain HTTP | CWE-319 |
| 12 | low | RED1 | HTTP redirect points to another host over plain HTTP | CWE-319 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 15 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 16 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 17 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 20 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 21 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 22 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 23 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |
| 24 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 25 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |
| 26 | info | CT1 | 44 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 11. [LOW] HTTPS root redirects to plain HTTP (`RED7`)

- **CWE:** CWE-319
- **Detail:** Location: http://www.boredpanda.com/
- **Context:** https response, /
- **Recommendation:** Redirect to an https:// target.

### 12. [LOW] HTTP redirect points to another host over plain HTTP (`RED1`)

- **CWE:** CWE-319
- **Detail:** Location: http://www.boredpanda.com/
- **Context:** https response, /
- **Recommendation:** Redirect to the same host over HTTPS.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 15. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 16. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=QyUw3s4mkxY3wZMMy4oMT3yHhdCqtiBuusYhmvAdgVM; google-site-verification=KIIUiAJna3_1-eDilP2A9ENUy2oiWftdyHXyCMhnz3s; anthropic-domain-verification-qp0t5e=qyjWbKPmD6hTz77lb10rBJ2hi
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 17. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 11 disallow path(s), e.g. /, /, /, /, /?s=
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 54.204.103.197 carries PTR ec2-54-204-103-197.compute-1.amazonaws.com. for boredpanda.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 20. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for boredpanda.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 21. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The boredpanda.com certificate lists an AIA OCSP responder (http://ocsp.r2m04.amazontrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 22. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on boredpanda.com lists 11 <loc> URL(s) across 12 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 23. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to boredpanda.com negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

### 24. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of boredpanda.com is http://ocsp.r2m04.amazontrust.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 25. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of boredpanda.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

### 26. [INFO] 44 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: 2.stage.boredpanda.com, api.backbone.boredpanda.com, api.boredpanda.com, api.ideas.boredpanda.com, assets.boredpanda.com, growthbook-api.internal.boredpanda.com, growthbook.internal.boredpanda.com, img.boredpanda.com, img.stage.boredpanda.com, jobs.boredpanda.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "boredpanda.com",
  "dns": {
    "a": [
      "54.204.103.197",
      "35.168.213.86",
      "44.220.98.194",
      "44.221.107.254"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 1)"
    ],
    "ns": [
      "ns-1425.awsdns-50.org.",
      "ns-972.awsdns-57.net.",
      "ns-1985.awsdns-56.co.uk.",
      "ns-173.awsdns-21.com."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=QyUw3s4mkxY3wZMMy4oMT3yHhdCqtiBuusYhmvAdgVM",
      "MS=ms42183495",
      "google-site-verification=KIIUiAJna3_1-eDilP2A9ENUy2oiWftdyHXyCMhnz3s",
      "anthropic-domain-verification-qp0t5e=qyjWbKPmD6hTz77lb10rBJ2hi",
      "facebook-domain-verification=fgwdxllanmj6qtcuvmke1si9ec60ia",
      "apple-domain-verification=hops-EdsP_znUZ0tgSnyMFqx9WcQ6J6CLUlLwNJuseY",
      "google-site-verification=E-VWzamHJVxn2aKoEbD2dNX18GG_rEuHAJIAcsZ9JQY",
      "v=spf1 a mx include:_spf.mlsend.com include:_spf.google.com include:spf.mailjet.com ~all",
      "google-site-verification=MxIMpuiT8s52Vltu5GksnMWb3AmEfjHaawL4ii8SD_Q",
      "MS=E04C457D679181C1054598D9F097241502D2B900",
      "google-site-verification=XuF5a9eahvWOgNLrh7WkeiFQpnIjdbpEgbWPZ0a1oYY",
      "trustpilot-one-time-verification-id=9eb08d90-b03e-4784-821f-4256acbae37d",
      "brevo-code:59ddf176bd2029a7dea7a297ba5967ef",
      "google-site-verification=7IVwsmZnsAkCK_7cAFwmFfKsOt-dEkibijx09hJfQhM"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:ipm7lrx@ar.glockapps.com,mailto:ipm5swv@ar.glockapps.com,mailto:dmarc_agg@vali.email; ruf=mailto:ipm7lrx@fr.glockapps.com,mailto:ipm5swv@fr.glockapps.com; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=www.boredpanda.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jan 30 00:00:00 2026 GMT",
    "notAfter": "Feb 27 23:59:59 2027 GMT",
    "san": [
      "www.boredpanda.com",
      "www.mirror.boredpanda.com",
      "boredpanda.com",
      "mirror.boredpanda.com"
    ],
    "days_left": 153,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "54.204.103.197",
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
      "origin": "https://sub.boredpanda.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.boredpanda.com:443/"
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
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 44,
    "notable": [
      "2.stage.boredpanda.com",
      "api.backbone.boredpanda.com",
      "api.boredpanda.com",
      "api.ideas.boredpanda.com",
      "assets.boredpanda.com",
      "growthbook-api.internal.boredpanda.com",
      "growthbook.internal.boredpanda.com",
      "img.boredpanda.com",
      "img.stage.boredpanda.com",
      "jobs.boredpanda.com",
      "mail.boredpanda.com",
      "news.boredpanda.com",
      "static.boredpanda.com",
      "static.social-tools.boredpanda.com"
    ],
    "sample": [
      "2.boredpanda.com",
      "2.stage.boredpanda.com",
      "api-read.boredpanda.com",
      "api.backbone.boredpanda.com",
      "api.boredpanda.com",
      "api.ideas.boredpanda.com",
      "app-api.boredpanda.com",
      "assets.boredpanda.com",
      "boredpanda.com",
      "community.boredpanda.com",
      "content.boredpanda.com",
      "gateway.boredpanda.com",
      "growthbook-api.boredpanda.com",
      "growthbook-api.internal.boredpanda.com",
      "growthbook.boredpanda.com",
      "growthbook.internal.boredpanda.com",
      "ideas-tool.boredpanda.com",
      "ideas.boredpanda.com",
      "img.boredpanda.com",
      "img.stage.boredpanda.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=QyUw3s4mkxY3wZMMy4oMT3yHhdCqtiBuusYhmvAdgVM",
    "google-site-verification=KIIUiAJna3_1-eDilP2A9ENUy2oiWftdyHXyCMhnz3s",
    "anthropic-domain-verification-qp0t5e=qyjWbKPmD6hTz77lb10rBJ2hi",
    "facebook-domain-verification=fgwdxllanmj6qtcuvmke1si9ec60ia",
    "apple-domain-verification=hops-EdsP_znUZ0tgSnyMFqx9WcQ6J6CLUlLwNJuseY"
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
      "aia_ocsp": "http://ocsp.r2m04.amazontrust.com",
      "serial": 19219253865206090562989976243229759022,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "san": [
        "www.boredpanda.com",
        "www.mirror.boredpanda.com",
        "boredpanda.com",
        "mirror.boredpanda.com"
      ],
      "subject_dn": "311b3019060355040313127777772e626f72656470616e64612e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20260130000000",
      "not_after": "20270227235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/",
      "/",
      "/",
      "/?s=",
      "/search/",
      "/*wp-admin/",
      "/*wp-includes",
      "/*wp-content",
      "/*wp-json",
      "/contributor/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-54-204-103-197.compute-1.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "http://www.boredpanda.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "sitemap": {
      "urls": 11,
      "indexes": 12
    },
    "crl": {
      "url": "http://crl.r2m04.amazontrust.com/r2m04.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "cipher_ver": "TLSv1.2",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "x17": {
    "ocsp_http": "http://ocsp.r2m04.amazontrust.com"
  },
  "elapsed_s": 57.0,
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
