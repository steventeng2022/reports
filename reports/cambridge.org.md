# Security Audit Report — cambridge.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cambridge.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | cambridge.org |
| Test date | 2026-09-27 02:21 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **26** (High: 0, Medium: 0, Low: 6, Info: 20)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 16 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 17 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 18 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 19 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 20 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 21 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 22 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 23 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |
| 24 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |
| 25 | info | CT1 | 75 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 26 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.17.111.190:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.17.111.190:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 12. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 15. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 16. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 17. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 18. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: formstack-domain-verification=bc1d27a650a1f333058871330e43d4c1; teamviewer-sso-verification=db65502554224be3a892d0a1d7d23ac7; parkable-domain-verification=tfyMMTd19z2TedD63DPVMyjFILPMgwM4IP7J2elpykE=
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 19. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of cambridge.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 20. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 70 disallow path(s), e.g. /, /, /, /aca/authorinformation/, /blocks
- **Recommendation:** Review disallowed paths; robots is not access control.

### 21. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on cambridge.org indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 22. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for cambridge.org, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 23. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to cambridge.org negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

### 24. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of cambridge.org declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

### 25. [INFO] 75 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.entries.cambridge.org, api.internal.aggregation.cambridge.org, cdn.authorservices.cambridge.org, dev.flowsource.cambridge.org, diff.api.internal.aggregation.cambridge.org, gitlab.aop.cambridge.org, gitlab.services.aop.cambridge.org, live.login.cambridge.org, login.authorhub-main-priv.uat.adnc.cambridge.org, login.authorhub-uat.adnc.cambridge.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 26. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: dev.flowsource.cambridge.org; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "cambridge.org",
  "dns": {
    "a": [
      "104.17.111.190",
      "104.17.110.190"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "eu-smtp-inbound-1.mimecast.com (pref 4)",
      "eu-smtp-inbound-2.mimecast.com (pref 4)"
    ],
    "ns": [
      "nucum.ns.cloudflare.com.",
      "lex.ns.cloudflare.com."
    ],
    "caa": [],
    "spf": [
      "formstack-domain-verification=bc1d27a650a1f333058871330e43d4c1",
      "Z8kBemfkazJ2i4ysd4p6BpfEKVVRKFT0hQCLeyk8itVhI7FgQo/fof5BCS1pgLO13FaYp+KaVmX2pPT7/mtD+Q==",
      "teamviewer-sso-verification=db65502554224be3a892d0a1d7d23ac7",
      "parkable-domain-verification=tfyMMTd19z2TedD63DPVMyjFILPMgwM4IP7J2elpykE=",
      "google-site-verification=-houjDGhv3j4boUHMyT2w-kmHVFMJBopLlqOV9CRtXE",
      "00D2000000000hs=1TBQt00000001Vd",
      "77b755eb-0c8f-462f-9071-e147b4823dba",
      "knowbe4-site-verification=6f2a12971b44215b655214e401300716",
      "amazonses:Hk45M0qWK+GZ2iX9XJ0TVVq2mc+DayOePbXsYVp/abQ=",
      "google-site-verification=iDXI17Esaf_WqUOMbG7t1tkZ3cD3I2B81texGDyCmLE",
      "docusign=8f67c3ac-0e31-428a-b89b-d6c05efbcc57",
      "onetrust-domain-verification=67ea4d2fa6f84245aa04d058118d26ad",
      "krp4xlxh54n2p0jgnklc2sy826wnbqfd",
      "apple-domain-verification=DhDDkLn3rLrZDuNx",
      "6mhwwb8qmrthfb7qmpjlkhr6w30yrqk7",
      "adobe-idp-site-verification=7d354030906008d5dcab28dc74cff0b4c3f868aa68415212c70801597f944dc8",
      "atlassian-sending-domain-verification=681c02b7-bef7-4652-a1c3-b5999a7056c2",
      "amazonses:q6HVI+PeonYnqfC7kDzNqCrUyIXQnena/tC1RgTQZ/s=",
      "google-site-verification=N5etRfpe1AcCZMdSJz5sVicQHzzIr9RbU9cQTjQ94vE",
      "apple-domain-verification=0z9Q3j82qURKE0jE",
      "have-i-been-pwned-verification=361b42c0181f1c91867b0c7731657e90",
      "56l0x50ygt1fkr23c9npqsrmwqr2cvhb",
      "MS=ms61882158",
      "atlassian-domain-verification=7S7bsIrOwlHLdBG0OLNWITmcgqmnW8uaUKxRjA4McIJx1ThN46eQh2TaacXbCKhR",
      "_qzf1ow8akt4j08t4s2mpxnfm03j00ap",
      "miro-verification=e0eb88c47512f1b3e347014c28cd69d732b8cc38",
      "figma-domain-verification=82306f7d5e6d9b44f70bf7e951c99627e467dcb0111c988d3ae2066031b18983-1755005759",
      "_7medm2uqul87tj3d47vgw0kjs7tvycm",
      "_9acsisu491ieex01chikb1wu70u61ev",
      "anthropic-domain-verification-mae9zt=OrJVGKqpLLCr3R2xm97n1UkaA",
      "google-site-verification=G2cATcZ2EVrpsOVGGF5MmI4kHQzXzEWHQ3MLXp2AmjI",
      "xwwmlgcbfg256thhdv0150228ks7rkzb",
      "amazonses:ivqwfLhOGGWGY27uhxdFOA4LwWOJLR+4cr1nUQ4Guh4=",
      "google-site-verification=RHYH2O4q7639HXg9OOtkhwU1GoSz2yrwFQ95dmHzArI",
      "_6rpwlgh7ul5lr5zxzlmlb7hpr2ejnqe",
      "confluent-verification=5cd8b60d-2121-4b7a-8dc9-6c3fb6a7bc43",
      "facebook-domain-verification=nkrm6s56pcmfep9h0lgko47xsxxml5",
      "00D8d0000059NJR=1TBSq00000004jZ",
      "zoho-verification=zb43177975.zmverify.zoho.com",
      "amazonses:ULRvjmdH/bCZZFgF/xINBm531pRwaQntnQRX/m4r5Zc=",
      "08261f74-adda-45ae-bab0-9b7e8919b7c7",
      "v=spf1 redirect=390fwuvj._spf._d.mim.ec",
      "0c333ae6-6e62-4dd3-bd75-bbbe8c00a9e3",
      "apple-domain-verification=dJCKMZtNMZrBxvyv",
      "SFMC-XCiRpahbO1482ub4X4SdBpTNt9_QuR4k5vr-azmb",
      "onetrust-domain-verification=e66d1551d1154391a5e51733b7fc58a8"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:047acbdc29a7625@rep.dmarcanalyzer.com,mailto:dmarc-admin@cambridge.org; ruf=mailto:047acbdc29a7625@rep.dmarcanalyzer.com,mailto:dmarc-admin@cambridge.org; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "subject": "commonName=cambridge.org",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep  9 05:21:18 2026 GMT",
    "notAfter": "Dec  8 06:21:14 2026 GMT",
    "san": [
      "cambridge.org",
      "resource.cambridge.org"
    ],
    "days_left": 72,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "104.17.111.190",
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
      "domain": "cambridge.org",
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
      "origin": "https://sub.cambridge.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 0,
    "error": "http connect failed"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 0",
    "/redirect?next=https://evil-auditor.example/x -> 0",
    "/go?url=https://evil-auditor.example/x -> 0",
    "/url?url=https://evil-auditor.example/x -> 0"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 0,
    "/.well-known/security.txt": 0,
    "/security.txt": 0,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 0,
    "/phpmyadmin/index.php": 0,
    "/server-status": 0,
    "/api/": 0
  },
  "subdomains": {
    "source": "certspotter",
    "count": 75,
    "notable": [
      "admin.entries.cambridge.org",
      "api.internal.aggregation.cambridge.org",
      "cdn.authorservices.cambridge.org",
      "dev.flowsource.cambridge.org",
      "diff.api.internal.aggregation.cambridge.org",
      "gitlab.aop.cambridge.org",
      "gitlab.services.aop.cambridge.org",
      "live.login.cambridge.org",
      "login.authorhub-main-priv.uat.adnc.cambridge.org",
      "login.authorhub-uat.adnc.cambridge.org",
      "login.dev.authorhub.cambridge.org",
      "login.ols-admin-qa.aop.cambridge.org",
      "login.ols-admin-si.aop.cambridge.org",
      "login.ols-ui-qa.aop.cambridge.org",
      "login.ols-ui-si.aop.cambridge.org"
    ],
    "sample": [
      "admin.entries.cambridge.org",
      "adnc.cambridge.org",
      "am-assessor.digitalexams5.cambridge.org",
      "api.internal.aggregation.cambridge.org",
      "apis.sandbox.usdt.cambridge.org",
      "apis.usdt.cambridge.org",
      "architecture-maps.cambridge.org",
      "audit.prd.entries.cambridge.org",
      "authorservices.cambridge.org",
      "bookshelf.cambridge.org",
      "cambridge.org",
      "cams.cambridge.org",
      "camsstaging.cambridge.org",
      "cdc.cambridge.org",
      "cdn.authorservices.cambridge.org",
      "cem-ns.cambridge.org",
      "click.updates.cambridge.org",
      "cuckoo.cambridge.org",
      "cuperpsbx01.ad.cambridge.org",
      "dev.flowsource.cambridge.org"
    ],
    "dangling": [
      "dev.flowsource.cambridge.org"
    ]
  },
  "apex_txt": [
    "formstack-domain-verification=bc1d27a650a1f333058871330e43d4c1",
    "teamviewer-sso-verification=db65502554224be3a892d0a1d7d23ac7",
    "parkable-domain-verification=tfyMMTd19z2TedD63DPVMyjFILPMgwM4IP7J2elpykE=",
    "google-site-verification=-houjDGhv3j4boUHMyT2w-kmHVFMJBopLlqOV9CRtXE",
    "knowbe4-site-verification=6f2a12971b44215b655214e401300716"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "serial": 285848010988184173656303825314514279524,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/we1/epTyZlbjMxw.crl"
      ],
      "san": [
        "cambridge.org",
        "resource.cambridge.org"
      ],
      "subject_dn": "311630140603550403130d63616d6272696467652e6f7267",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531",
      "not_before": "20260909052118",
      "not_after": "20261208062114"
    }
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/",
      "/",
      "/aca/authorinformation/",
      "/blocks",
      "/concrete",
      "/config",
      "/controllers",
      "/css",
      "/elements",
      "/helpers",
      "/jobs",
      "/js",
      "/languages",
      "/libraries"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.cambridge.org",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "crl": {
      "url": "http://c.pki.goog/we1/epTyZlbjMxw.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "cipher_ver": "TLSv1.2",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "x17": {},
  "elapsed_s": 404.3,
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
