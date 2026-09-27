# Security Audit Report — redbull.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://redbull.com/ |
| Bug bounty program | Redbull |
| Listed scope domain | redbull.com |
| Test date | 2026-09-27 02:43 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 4, Info: 15)

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
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 17 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 18 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 19 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
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
- **Detail:** Header reveals: AkamaiGHost
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
- **Detail:** Apex TXT records with verification/token content: workplace-domain-verification=G6JbgsDS3rGKm9xjdExKVXP3uazq8P; zapier-domain-verification-challenge=112b278f-86f3-41a1-896b-d581fb935e34; yandex-verification: aad18f620b64b27c
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.208.12.170 carries PTR a23-208-12-170.deploy.static.akamaitechnologies.com. for redbull.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for redbull.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 17. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The redbull.com certificate lists an AIA OCSP responder (http://ocsp.sectigo.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 18. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on redbull.com identify the edge as Akamai; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 19. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of redbull.com is http://ocsp.sectigo.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

## Evidence (raw response observations)

```json
{
  "domain": "redbull.com",
  "dns": {
    "a": [
      "23.208.12.170",
      "23.208.12.186"
    ],
    "aaaa": [
      "2600:1417:8400:31::17ce:cb47",
      "2600:1417:8400:31::17ce:cb59"
    ],
    "cname": null,
    "mx": [
      "redbull-com.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "ns15.ultradns2.com.",
      "pdns91.ultradns.biz.",
      "ns15.ultradns2.org.",
      "pdns91.ultradns.org.",
      "pdns91.ultradns.net.",
      "pdns91.ultradns.com."
    ],
    "caa": [],
    "spf": [
      "workplace-domain-verification=G6JbgsDS3rGKm9xjdExKVXP3uazq8P",
      "MS=ms97463818",
      "zapier-domain-verification-challenge=112b278f-86f3-41a1-896b-d581fb935e34",
      "yandex-verification: aad18f620b64b27c",
      "atlassian-domain-verification=SE0bg/sLbNj/sxFjb5WzNowyB2EHWNhe/j4JbSYgLllAii8XsA6kVaTiLiQS7Kr7",
      "monday-com-verification=qVsHJCKBqguw6NvEWYm9FSUma88aPXmBM__iEh_LcdU",
      "webexdomainverification.C5UR=281b4db8-b67c-4111-9ece-8958b41cd08f",
      "mongodb-site-verification=s4RGRapyJSjdREFYPXqvzHmYt60COynM",
      "google-site-verification=wjAcjCp-XN8rKlZWz47ImMiC6gYoaVe5So6Yl7YhHk0",
      "adobe-idp-site-verification=f7adf3e3b2e02fdafc5d0da23da483f36bbf68c3d554a3bb94db66190116545f",
      "_ryr62gyfim9w9j6y96gb4hido52o87c",
      "yandex-verification: a51dcd774998eab8",
      "ciscocidomainverification=484a6f952eb1e97a5d6a12260122d88095307403a3c873f524b55a8a09e0311c",
      "spycloud-domain-verification=7b0d7b29-0783-43a8-ae02-2618020eb9d0",
      "virtru-site-verify=obp3KuFTAvVACEbB28a2PkjY9bvEQhygmi7gd3d6",
      "apple-domain-verification=odkhNiY1AwjKsHAl",
      "google-site-verification=zdiNmEZSzIJoZazEYew3bFFSXqudF7ODAHqljjf9hjg",
      "uber-domain-verification=345f84e7-8f29-4772-8a95-437d5755fd97",
      "ZOOM_verify_m27rLBztRkeFHLDKbAtzuA",
      "firebase=redbull-photobooth-fansite",
      "fastly-domain-delegation-l6ByU9UvR9NX06q-20251121",
      "facebook-domain-verification=uhk1v8zuggj2ug6q0e9f1hczlzz1jr",
      "globalsign-domain-verification=hL1YyaIXzf8_UoxDhIMWaHVWUANe7eU7dWvXus7lwI",
      "notion-domain-verification=hN2mHaKh119t9oIeUxOZ3tMcWasvrx4wAOUBR7gEgfY",
      "canva-site-verification=CpUH3-GXSXlisKiHbnI6kw",
      "amazonses:pkdkj6bcdiVxa2xtsoMA70kc1PyYjNtUzGcLZGHWXQk=",
      "jamf-site-verification=_T1tJfEpBa5y1V4i5ongPw",
      "docusign=679758f7-e6bc-41ab-8dbf-417624c378a4",
      "vector-saml-92020417",
      "Ws0bd7f6/5qF5IIq/WdhyrANdPcnsIiWWLi0IaWO5cKb/CFj6cBCGx2siy/4UFRc0e2FMOB0+FUmWeos/leuYg==",
      "teamviewer-sso-verification=3d50f93de59b453aa294796293a115d0",
      "neat-pulse-domain-verification-W8XZ4xN=35c9459f-5f1d-48dc-a8dc-fcd480a2e5f1",
      "atlassian-sending-domain-verification=3531ce11-63aa-453d-a854-4ab6aad86fcf",
      "figma-domain-verification=7a82465e7631432ddae7da5c5874d4fd7bdefc2c5eabd1baca75d219dc388f58-1725268196",
      "f7fbf1eb4bb2bd20afa0e38447eff8dc3d66a2c953e59e527a",
      "cm.com-domain-verification=648a8834-79b1-4072-9fcc-01a85c8f8c22",
      "google-site-verification=x_6pn1VmeoS7F3VrlNiZye1yb0RXleXiW2psI9flRBY",
      "docusign=b3640d57-0668-4c84-a5cb-4e199fd00d38",
      "google-site-verification=cAAOttK7KB-rKBmOD7p1Imx6EcdvKD-DLIvoDclN8YA",
      "TGTRxhxdWsMPjij6aytGGneMBuVXCl/yZnJjLxOrka4s+20mUfT10boKi26Gucz3BPhpnzjLSLk+ktKl9sGJxw==",
      "v=spf1 include:spf.protection.outlook.com include:_spf.redbull.com include:spf.virtrugateway.com -all",
      "atlassian-domain-verification=6JjO48MB9UypL10pMDk0vdlEGRGtdMztJavx3KTtMJerMz/adr2Ks0qr+55+LpoQ",
      "google-site-verification=dyaNOA-sacV_MOg8KnODyK8ihwNa368Vz0Hq2_5MpcY",
      "_uy14g9zokx3stw6c10e7kacxl2krs0h",
      "anthropic-domain-verification-5wg0q8=Drbo9cZiHvN1d2LNdDTEpoRku",
      "google-site-verification=FT9NwKVuURPQaWb5Fq7oVSA7l5r_OebpkZ8ySQLlOIY",
      "QuoVadis=d56f7361-359a-4f04-b858-2e34d9d9b117"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:zsrbf6su@ag.eu.dmarcadvisor.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=AT, stateOrProvinceName=Salzburg, organizationName=Red Bull GmbH, commonName=redbull.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA OV E36",
    "notBefore": "Aug 13 00:00:00 2026 GMT",
    "notAfter": "Feb 27 23:59:59 2027 GMT",
    "san": [
      "redbull.com",
      "www.redbull.com"
    ],
    "days_left": 153,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.208.12.170",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.redbull.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.redbull.com/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "workplace-domain-verification=G6JbgsDS3rGKm9xjdExKVXP3uazq8P",
    "zapier-domain-verification-challenge=112b278f-86f3-41a1-896b-d581fb935e34",
    "yandex-verification: aad18f620b64b27c",
    "atlassian-domain-verification=SE0bg/sLbNj/sxFjb5WzNowyB2EHWNhe/j4JbSYgLllAii8XsA",
    "monday-com-verification=qVsHJCKBqguw6NvEWYm9FSUma88aPXmBM__iEh_LcdU"
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
      "aia_ocsp": "http://ocsp.sectigo.com",
      "serial": 143344266984103675328473705200101065524,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.sectigo.com/SectigoPublicServerAuthenticationCAOVE36.crl"
      ],
      "san": [
        "redbull.com",
        "www.redbull.com"
      ],
      "subject_dn": "310b30090603550406130241543111300f0603550408130853616c7a6275726731163014060355040a130d5265642042756c6c20476d6248311430120603550403130b72656462756c6c2e636f6d",
      "issuer_dn": "310b300906035504061302474231183016060355040a130f5365637469676f204c696d69746564313730350603550403132e5365637469676f205075626c6963205365727665722041757468656e7469636174696f6e204341204f5620453336",
      "not_before": "20260813000000",
      "not_after": "20270227235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a23-208-12-170.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.redbull.com/",
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
    "crl": {
      "url": "http://crl.sectigo.com/SectigoPublicServerAuthenticationCAOVE36.crl",
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
    "cdn": [
      "Akamai"
    ]
  },
  "x17": {
    "ocsp_http": "http://ocsp.sectigo.com"
  },
  "elapsed_s": 11.1,
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
