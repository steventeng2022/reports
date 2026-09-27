# Security Audit Report — airtable.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://airtable.com/ |
| Bug bounty program | Airtable |
| Listed scope domain | airtable.com |
| Test date | 2026-09-27 01:08 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 4, Info: 20)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 7 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 14 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | low | CK8 | Session-like cookie with >=30-day lifetime | CWE-613 |
| 17 | low | CK8 | Session-like cookie with >=30-day lifetime | CWE-613 |
| 18 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 19 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 20 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 21 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 22 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 23 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 24 | info | CT1 | 65 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Tengine
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Tengine
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'AWSALBTG' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 7. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'AWSALBTG' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

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
- **Detail:** Apex TXT records with verification/token content: docker-verification=d352c009-156f-4f43-a6c9-19c62d5f7f39; google-site-verification=AqsnhsVuEKjGgLyc8RXu6W3IPYDj-805B5Ofrt4ubp8; drift-domain-verification=25a66e35596d2f8afdc380e147dc2c84a92afd4020ca912c4eece0
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 17 disallow path(s), e.g. /404, /500, /auth, /embed/*, /temporary_marketing_proxy/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of airtable.com permits unsafe-inline; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 14. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of airtable.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.169.55.126 carries PTR server-3-169-55-126.tpe54.r.cloudfront.net. for airtable.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [LOW] Session-like cookie with >=30-day lifetime (`CK8`)

- **CWE:** CWE-613
- **Detail:** Cookie '__Host-airtable-session' on airtable.com is session-like but carries a Max-Age/Expires lifetime of 30 days or more; a stolen cookie stays valid for a long window.
- **Recommendation:** Shorten session-cookie lifetime and/or require re-authentication for sensitive actions.

### 17. [LOW] Session-like cookie with >=30-day lifetime (`CK8`)

- **CWE:** CWE-613
- **Detail:** Cookie '__Host-airtable-session.sig' on airtable.com is session-like but carries a Max-Age/Expires lifetime of 30 days or more; a stolen cookie stays valid for a long window.
- **Recommendation:** Shorten session-cookie lifetime and/or require re-authentication for sensitive actions.

### 18. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xku5pur0dc79ba.html -> 404; error page/headers match: CloudFront.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 19. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on airtable.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 20. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for airtable.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 21. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on airtable.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 22. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on airtable.com lists 2027 <loc> URL(s); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 23. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on airtable.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 24. [INFO] 65 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.airtable.com, app.airtable.com, app.staging.airtable.com, blog.airtable.com, content.staging.airtable.com, dl.staging.airtable.com, dl3.staging.airtable.com, dl5.staging.airtable.com, domains.staging.airtable.com, hooks.staging.airtable.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "airtable.com",
  "dns": {
    "a": [
      "3.169.55.126",
      "3.169.55.6",
      "3.169.55.74",
      "3.169.55.99"
    ],
    "aaaa": [
      "2600:9000:2834:b600:0:fde1:c980:93a1",
      "2600:9000:2834:a400:0:fde1:c980:93a1",
      "2600:9000:2834:1600:0:fde1:c980:93a1",
      "2600:9000:2834:3c00:0:fde1:c980:93a1",
      "2600:9000:2834:5c00:0:fde1:c980:93a1",
      "2600:9000:2834:e200:0:fde1:c980:93a1",
      "2600:9000:2834:b800:0:fde1:c980:93a1",
      "2600:9000:2834:4a00:0:fde1:c980:93a1"
    ],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-685.awsdns-21.net.",
      "ns-447.awsdns-55.com.",
      "ns-1069.awsdns-05.org.",
      "ns-1899.awsdns-45.co.uk."
    ],
    "caa": [],
    "spf": [
      "docker-verification=d352c009-156f-4f43-a6c9-19c62d5f7f39",
      "v=spf1 ip4:159.135.229.248 ip4:159.135.231.62 ip4:69.72.44.244 include:_spf.mailgun.org include:_spf.google.com include:_spf.salesforce.com mx ~all",
      "google-site-verification=AqsnhsVuEKjGgLyc8RXu6W3IPYDj-805B5Ofrt4ubp8",
      "drift-domain-verification=25a66e35596d2f8afdc380e147dc2c84a92afd4020ca912c4eece0fe0ba31b07",
      "sprout-social-092bd800-f204-4740-bf84-ae806843855d",
      "zapier-domain-verification-challenge=8ee12b84-1c1e-467a-bbbf-a8f5f30f442e",
      "box-domain-verification=7b0f06dc1db321da4355e0a57264582ef993ea8d5ec6a6a535c0da1fbb3716c4",
      "google-site-verification=DXt7gC5fDi-TwbqBj4qhJ0xZolvejBEbmsnmAWmid90",
      "ibmid=0555764c-fa27-4142-a90e-2ceb610f84ff",
      "mgverify=c76c0b58ab94a58ab6470a3648cd01d386e0eded8faff1fe936c0f51605886c6",
      "stripe-verification=528727982b9408fcfaf4799d022aed98e6fe59f7bd19fb80c19eddf770808454",
      "google-site-verification=euX05KyKBY2XRY3sMd51MBgkLgWSDt-D6HxEPbJZE4E",
      "onetrust-domain-verification=08cafae7e510435994fd87812abaa805",
      "postman-domain-verification=403414135fdd4de22ea8e6924a70b46d821cf0de2e9555c4b96e41c60231c9d84c37489d47b347411f991b446b0a7e0050b0bbff390999842ce3cc8c11cf8a93",
      "openai-domain-verification=dv-cLdaKW0SF1WwsRiJz5GPTU3z",
      "MS=ms57543645",
      "google-site-verification=jCY0WH76zs_XUIsPN-CpVMrGxoER14S-qmba5HB-NOw",
      "google-site-verification=O-kfeG0vtUgAjQYn-gDpWkYWb_Kl8f3z9OjKswYlDug",
      "atlassian-domain-verification=SEoCkU1vByxZ6STi0tknyHIzfSDxB1F6wGGf/phI3fHsyIuu4doRXS/fXd0oadkC",
      "google-site-verification=7OYI2dFV51swegn-yfn7A9M6JKMyCLwnwVcoHriMkgw",
      "mgverify=4e7a1ef686139875f21ee18e629284f4b32b4bef29516a48d42806937db7489f",
      "TAILSCALE-LCbD2Tan8BItnHOB3y0p",
      "beam-verification=Z9ucVlrllzaQ5SpJiJltJUsYSnHkBBIBjKadv4gsv5gddutH",
      "jamf-site-verification=rHp6jc3H-3QFQbAJCz28xA",
      "cursor-domain-verification-7etnx9=AnyVPVFCmQJv6S6Hy1hH9cMUx",
      "google-site-verification=dKKmkVVrUbTHz22G3Mouc0xGoi_asVZMFspACVKmJoM",
      "facebook-domain-verification=gfg0qo2au8cywd132m0itehi8rqhfq",
      "pylon-domain-verification-rhyhge=10SPcgfAp1cUzFOD1rW7HK9o6",
      "apple-domain-verification=p7c2orfu38a1od5v",
      "docusign=48aed6b7-99ce-449e-b576-0e32ac39a3ca",
      "v=MCPv1; k=ed25519; p=G1cCoFkb5x1fTZwAJLb42JSNQB/sT9Cyx+colhPq7YI=",
      "cloudflare_dashboard_sso=c69d6361128a7dad5039e5b76e9b2cde",
      "google-site-verification=yvhp-gxMyp-JZnuAm8Jx_EEoEjdik7VFz-wCpC4fklQ"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; ri=3600; rua=mailto:dc7a0f9c@dmarc.mailgun.org,mailto:b38def86@inbox.ondmarc.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=app.airtable.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jul 13 00:00:00 2026 GMT",
    "notAfter": "Jan 26 23:59:59 2027 GMT",
    "san": [
      "app.airtable.com",
      "airtable.com"
    ],
    "days_left": 121,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.55.126",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Tengine"
  ],
  "cookies": [
    {},
    {
      "samesite": "none"
    },
    {
      "domain": ".airtable.com",
      "samesite": "none"
    },
    {
      "domain": ".airtable.com",
      "samesite": "none"
    },
    {
      "domain": ".airtable.com"
    },
    {
      "samesite": "none"
    },
    {
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
      "origin": "https://sub.airtable.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://airtable.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 65,
    "notable": [
      "api.airtable.com",
      "app.airtable.com",
      "app.staging.airtable.com",
      "blog.airtable.com",
      "content.staging.airtable.com",
      "dl.staging.airtable.com",
      "dl3.staging.airtable.com",
      "dl5.staging.airtable.com",
      "domains.staging.airtable.com",
      "hooks.staging.airtable.com",
      "mcp.staging.airtable.com",
      "share.support.airtable.com",
      "staging.airtable.com",
      "static.airtable.com",
      "static.staging.airtable.com"
    ],
    "sample": [
      "academy.airtable.com",
      "airspace.airtable.com",
      "airtable.com",
      "api-staging.airtable.com",
      "api.airtable.com",
      "api2-staging.airtable.com",
      "api2.airtable.com",
      "app.airtable.com",
      "app.staging.airtable.com",
      "blog.airtable.com",
      "brand.airtable.com",
      "community.airtable.com",
      "content.airtable.com",
      "content.staging.airtable.com",
      "dl.airtable.com",
      "dl.staging.airtable.com",
      "dl3.airtable.com",
      "dl3.staging.airtable.com",
      "dl5.airtable.com",
      "dl5.staging.airtable.com"
    ]
  },
  "apex_txt": [
    "docker-verification=d352c009-156f-4f43-a6c9-19c62d5f7f39",
    "google-site-verification=AqsnhsVuEKjGgLyc8RXu6W3IPYDj-805B5Ofrt4ubp8",
    "drift-domain-verification=25a66e35596d2f8afdc380e147dc2c84a92afd4020ca912c4eece0",
    "zapier-domain-verification-challenge=8ee12b84-1c1e-467a-bbbf-a8f5f30f442e",
    "box-domain-verification=7b0f06dc1db321da4355e0a57264582ef993ea8d5ec6a6a535c0da1f"
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
      "aia_ocsp": "http://ocsp.r2m04.amazontrust.com",
      "serial": 10128933457841511569321288890911727803,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "subject_dn": "31193017060355040313106170702e6169727461626c652e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20260713000000",
      "not_after": "20270126235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/404",
      "/500",
      "/auth",
      "/embed/*",
      "/temporary_marketing_proxy/*",
      "/forgot",
      "/internal/*",
      "/invite/l?inviteId=*&inviteToken=*",
      "/msa",
      "/shr*",
      "/app*/shr*",
      "/app*/pag*/form*",
      "/sso/login",
      "/tbl*",
      "/?try=*"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "server-3-169-55-126.tpe54.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.airtable.com/",
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
      "/.well-known/assetlinks.json"
    ],
    "stapling": "inconclusive",
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
    "sitemap": {
      "urls": 2027,
      "indexes": 0
    },
    "crl": {
      "url": "http://crl.r2m04.amazontrust.com/r2m04.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "cdn": [
      "CloudFront",
      "Fastly"
    ]
  },
  "elapsed_s": 15.5,
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
