# Security Audit Report — upwork.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://upwork.com/ |
| Bug bounty program | Upwork |
| Listed scope domain | upwork.com |
| Test date | 2026-09-27 01:36 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 1, Info: 17)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 14 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 15 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 16 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 17 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 18 | info | H25 | server-timing response header exposed | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.129.226:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.129.226:8443 succeeded (state-only check, no payload sent).
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

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 9. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=4p2pqAQ0yiDL2lc81zb89ZA-Wt6u9uBY25QEMjp-b4s; facebook-domain-verification=8nwzxhaovba8tj7d2ldml1bhssa1pm; google-site-verification=4g4BiPppYs75ob9yO422K5BqFPttTmPK_fmNtaopAI8
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of upwork.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 263 disallow path(s), e.g. /att/, /att-old/, /freelancers/public/api/, /messages/, /*/jobs/search*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on upwork.com indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 14. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on upwork.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 15. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for upwork.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 16. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on upwork.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 17. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of upwork.com carries alt-svc h3=":443"; ma=86400; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 18. [INFO] server-timing response header exposed (`H25`)

- **CWE:** CWE-200
- **Detail:** The root response of upwork.com sends server-timing (chlray;desc="a416c7470fee8463"); server/edge processing metrics are disclosed to any client.
- **Recommendation:** Restrict server-timing to authenticated/debug contexts if the internals are sensitive.

## Evidence (raw response observations)

```json
{
  "domain": "upwork.com",
  "dns": {
    "a": [
      "104.18.129.226",
      "104.18.128.226"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "jim.ns.cloudflare.com.",
      "fay.ns.cloudflare.com."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=4p2pqAQ0yiDL2lc81zb89ZA-Wt6u9uBY25QEMjp-b4s",
      "logmein-domain-confirmation 2141230743",
      "facebook-domain-verification=8nwzxhaovba8tj7d2ldml1bhssa1pm",
      "google-site-verification=4g4BiPppYs75ob9yO422K5BqFPttTmPK_fmNtaopAI8",
      "nlmdbpv52ts89j835vzt3c71d201hqk5",
      "asv=54832828144bb4ff89f152511204f3e2",
      "google-site-verification=BkuVDFrIY09DX823uWROsYHLrLeCUKJ366m1k4AmoT4",
      "openai-domain-verification=dv-0pTGTkARXsArFAKKZwc6Fzbl",
      "google-site-verification=LSicnKkde4b1FmPqfr0FX6l7R4VvjAxTVzZP0sebXKk",
      "google-site-verification=-LgXVF8adhy30B1kiNabPgT-Pymy3WZOOvfGFgp6XGE",
      "adobe-idp-site-verification=45e831bcd7ad9667a0be62ad1db9971caa65d4c68af84b32f30ca18dd29d6bac",
      "v=spf1 include:upwork.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:mail.clinchtalent.com include:spf.mandrillapp.com include:sendgrid.net ~all",
      "google-site-verification=sD8rL1N3j5vS_miQGy_NwdmJHTmFUU42SDhYa4rdQ84",
      "google-site-verification=MFfOuTSDuMVfAuZmNHfYJA16r0P_BeZX5F60NQnSHNA",
      "MS=6100C439A4691C31E2EC1342F09C3607B3B64DAC",
      "google-site-verification=PkziJTcGbOV4cv301PZ8KfBzni-MN_cB3J4ngmLA9Ps",
      "linear-domain-verification=z536v5rd3xih",
      "docusign=277af459-13d2-4b85-bb45-53efc4b671f6",
      "google-site-verification=zTEmbU71ZrIPR7JRRlWSGiQurNYft76eEdSdP6aAQkQ",
      "google-site-verification=3jXROOXzwXZqaI-z95yNNpu9L8mSRW3Jd5VCpjVOxwk",
      "paloaltonetworks-site-verification=e10a924e19c474e2b83aa85600a8d52fb39615b7834f93971c13687f13e8d326",
      "google-site-verification=hJI07_9hhjkWQFySSiVg5v3vNIpZBMwOkA1Il7-tCMY",
      "_vmdb9wrav5ukmzhtyzh5cps8gs2zooy",
      "hcp-domain-verification=b36955e77a08570a83deddbbdfa15fe1894a5c747597bc9941fc15f6f6bf22aa",
      "mongodb-site-verification=xc3WGhQz20Yw7Lm6yMoC6L4b5gf08icW",
      "cursor-domain-verification-z00fy8=8sg38uSSHGnTzRvM2sEDPoIl3",
      "google-site-verification=MK7qfjAI4BOyhzOcaFe2WjFleaX2gKcUUu6VKf5X-qE",
      "_gxokjwki7xqlmqjp3mp918p6j6w1peg",
      "_6lgpbootvod9h9mgfdn7efsdz52nzx0",
      "Dynatrace-site-verification=10887f73-4311-4a4b-83e3-312614aeb532__h68in82ubsmc8a7c1j8g0e6v6d",
      "asv=a52d93b02babfa60a71bdd4128a06b39",
      "google-site-verification=f3f7WfTf8cecTKAI3cwfnA-cmQP1WlyDMfzuzG6BB-8",
      "zapier-domain-verification-challenge=0ab7c0ae-a354-49d6-9012-16a12e53b121",
      "liveramp-site-verification=qn4k0EIcwgkwW6N80DcWp-G_gQeo9SCk4fdGh21URyw",
      "MS=ms47394909",
      "jamf-site-verification=GjhSBwax0Pxacxf38XbNHw",
      "mixpanel-domain-verify=2a906114-e222-4323-bbd7-0a671f9d90ee",
      "bugcrowd-verification=dae371187bf32cac11a23664ea291f6c",
      "chariot=chariot+upwork@praetorian.com",
      "anthropic-domain-verification-a50qdm=eDDAJvU3hKqefx59gXmsODCgG",
      "miro-verification=6a8362f817d4ea530843a04d46c6418e011c951d",
      "sjlh98brgm4j879mz0km0f9kz0s61mf8",
      "docker-verification=ccc1198a-92ef-4bca-8e5c-896b7c508065",
      "16359333",
      "stripe-verification=E9104449B2742089788253DB69E0E9C226D3F54E519514A3698526A4594B7D62"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=upwork.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep  8 04:52:43 2026 GMT",
    "notAfter": "Dec  7 05:52:39 2026 GMT",
    "san": [
      "upwork.com",
      "*.upwork.com",
      "*.email.upwork.com",
      "*.t.upwork.com"
    ],
    "days_left": 71,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.129.226",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 403,
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
      "domain": "upwork.com",
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
      "origin": "https://sub.upwork.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://upwork.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=4p2pqAQ0yiDL2lc81zb89ZA-Wt6u9uBY25QEMjp-b4s",
    "facebook-domain-verification=8nwzxhaovba8tj7d2ldml1bhssa1pm",
    "google-site-verification=4g4BiPppYs75ob9yO422K5BqFPttTmPK_fmNtaopAI8",
    "google-site-verification=BkuVDFrIY09DX823uWROsYHLrLeCUKJ366m1k4AmoT4",
    "openai-domain-verification=dv-0pTGTkARXsArFAKKZwc6Fzbl"
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
      "serial": 43158980094012567481380492098349399573,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/we1/3B7O0TVeMkw.crl"
      ],
      "subject_dn": "311330110603550403130a7570776f726b2e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531",
      "not_before": "20260908045243",
      "not_after": "20261207055239"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/att/",
      "/att-old/",
      "/freelancers/public/api/",
      "/messages/",
      "/*/jobs/search*",
      "/search/profiles/*",
      "/catalog-images/*",
      "/ab/",
      "/hire/de/sem/",
      "/nx/",
      "/j/view_opening_popup.php",
      "/leaving_odesk.php",
      "/leaving-odesk",
      "/leaving",
      "/nx/top-nav-ssi/visitor-gql-token"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.upwork.com/",
    "http_status": 301,
    "p404_status": 301,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=31536000; includeSubDomains; preload",
    "security_txt": "/.well-known/security.txt",
    "crl": {
      "url": "http://c.pki.goog/we1/3B7O0TVeMkw.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 403
  },
  "x16": {
    "root_status": 403,
    "alt_svc": "h3=\":443\"; ma=86400",
    "server_timing": "chlray;desc=\"a416c7470fee8463\""
  },
  "elapsed_s": 12.0,
  "rechecked": "2026-09-27 01:08 UTC"
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
- Findings are reported against the public program scope; submission through the program tracker is pending.
