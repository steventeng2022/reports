# Security Audit Report — ea.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ea.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ea.com |
| Test date | 2026-09-27 01:17 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **27** (High: 0, Medium: 0, Low: 6, Info: 21)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 11 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 12 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 13 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 14 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 15 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 16 | info | P8 | Missing security.txt | CWE-1038 |
| 17 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 18 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 19 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 20 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 21 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 22 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 23 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 24 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 25 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 26 | info | CT1 | 1797 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 27 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=93600
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'EDGESCAPE_COUNTRY' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 11. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'EDGESCAPE_COUNTRY' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 12. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'EDGESCAPE_REGION' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 13. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'EDGESCAPE_REGION' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 14. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'EDGESCAPE_TIMEZONE' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 15. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'EDGESCAPE_TIMEZONE' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 16. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 17. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 18. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 19. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: apple-domain-verification=AYQE6OxMih12JCzk; parsec-domain-verification=td_2PekalqDxqm3NIcvbo3Megt72X9; google-site-verification=HYdRtN3xk_TxaVDfhAVQb-Qbav7wj57E01Pci8x3oOg
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 20. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but ea.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 21. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://ea.com/ carries Cache-Control: max-age=0; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 22. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.209.216.194 carries PTR a23-209-216-194.deploy.static.akamaitechnologies.com. for ea.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 23. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for ea.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 24. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of ea.com carries alt-svc h3=":443"; ma=93600; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 25. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on ea.com identify the edge as Akamai; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 26. [INFO] 1797 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: 1.dev.gs.ea.com, 1.fc.qa.chat.gameservices.ea.com, 1.lt.chat.gs.ea.com, 10.dev.gs.ea.com, 10.fc.qa.chat.gameservices.ea.com, 10.lt.chat.gs.ea.com, 11.dev.gs.ea.com, 11.fc.qa.chat.gameservices.ea.com, 11.lt.chat.gs.ea.com, 12.dev.gs.ea.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 27. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: 1.dev.gs.ea.com, 1.fc.qa.chat.gameservices.ea.com, 1.lt.chat.gs.ea.com, 10.dev.gs.ea.com, 10.fc.qa.chat.gameservices.ea.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "ea.com",
  "dns": {
    "a": [
      "23.209.216.194"
    ],
    "aaaa": [
      "2600:1417:76:4a1::1127",
      "2600:1417:76:481::1127"
    ],
    "cname": null,
    "mx": [
      "ea-com.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "a13-67.akam.net.",
      "a4-64.akam.net.",
      "a8-67.akam.net.",
      "a7-66.akam.net.",
      "a1-164.akam.net.",
      "a6-65.akam.net."
    ],
    "caa": [],
    "spf": [
      "apple-domain-verification=AYQE6OxMih12JCzk",
      "parsec-domain-verification=td_2PekalqDxqm3NIcvbo3Megt72X9",
      "google-site-verification=HYdRtN3xk_TxaVDfhAVQb-Qbav7wj57E01Pci8x3oOg",
      "Console2714e2e7-3fa3-4b34-8693-c09b1d9986c6",
      "smartsheet-site-validation=2s81-L1kix0MAeJQmj44rEehwVlCUIYV",
      "adobe-sign-verification=c3b24a9842e8e22172e2568873e4ed3b",
      "QfGw4p+QlBkLTkHaJRQrTAHpN+ZgoZENi4uAnKBoQVVKGMBBhCzqeTpmndH2fHvajdi9FWSCrdQrPwQ7hzZMDA==",
      "ms-domain-verification=3e25dee7-ae46-448e-b9b9-20a6490f7af8",
      "adobe-idp-site-verification=b36e2eb4-d986-4903-a5be-15e3651396cf",
      "work-accounts-domain-verification=yeSmLL1AKrKom6NYUJRpBGBjrmRkCD",
      "cisco-ci-domain-verification=4cb82531e58e0b3c12afb359f5142eb4d461e0e589eefa3603a9af7317a8afd2",
      "google-site-verification=W_cWHGmP5RqmA9hYnm8inTTb9Sau7q1Ro911CH4SrZ8",
      "lookingglassweb.azurewebsites.net",
      "MS=ms19667016",
      "amazonses:SMeDjsim2TRE1HOX7bQmJJhBjV2DZPdakNXVtC1U5QA=",
      "facebook-domain-verification=oq80s5pdyo1d8huizochkuyscyewf2",
      "snowflake-verification=71ba1450-019f-1000-8718-000000000413",
      "amazonses:f11tLfH2vr9OwsWpUEXnb+wXe8KNcen1j3Lk5fK4W7U=",
      "mongodb-site-verification=cPx4xoyitTn3W8MmDPht4i7jYkP8v55b",
      "v=DMARC1;",
      "p=none;",
      "fo=1;",
      "rua=mailto:yesmail@rua.agari.com;",
      "ruf=mailto:yesmail@ruf.agari.com",
      "google-site-verification=QO6a-pP_siI7I6KAzi6Lj_GMmKik10qnGpIa-qDiaSs",
      "atlassian-domain-verification=TcMmJBl8jkffKRnLX0s82TVPAOBmzFE8N1xCvCg42ehCFfU8nxO1rMZcSCLdiIMh",
      "lovable_verification=wZkgBHNGXK1sMxUCtqNt",
      "tiktok-developers-site-verification=UWDwy70DCmMmCerrJX6oV1pRGABPapRe",
      "AagMut9FoA4ka4DYvu3QvUa5FRJCN4esFVQ3RG6RdGAjA8hTAlxLXme7sSHZnFDNX7XAPe5BIIbg1G23k2oVow==",
      "amazonses:mgCkNYnAkmnZtXK6zLrZW+THRSUyJZGJnSOBdj+isYU=",
      "google-site-verification=T8NmTlNnB0xPkycfop5hMmOAVQSivlmA4d8Y7--2x6U",
      "google-site-verification=069b0lSxMIobzf7rJTBnXqb1KDTmfFhsJMm8mP9xnBU",
      "anthropic-domain-verification-g53wq8=Hgm9Dc1mrdVQjGxnZWm4CSgri",
      "docker-verification=4bfce2f1-7d0f-474e-a43b-d60d18b35182",
      "shopify-verification-code=oarXm8VVyw5BycTVUZS53HSydl24Ba",
      "tiktok-developers-site-verification=VcYwjcEIoOmPFODSYEQjCUP09jElnNkn",
      "google-site-verification=JPqUmrL51cf3BGW7dM_RP70SaOhgCQpfVmfEWE4JWS0",
      "google-site-verification=dSC8gq7vptNeGVIDEpGQZ0xE8s-5BBIbc1r6R3_PwT0",
      "01E6D34C64F24201EE75D6BB52FD49ECA8E7F05E57CFC5D9963DFE28F5DD793B",
      "amazonses:h4cXsZhHgq6fK4DGoUQgriYwSeE6hO5aJ+h6wHnx/fk=",
      "tiktok-developers-site-verification=gZsAdTrtYEO38BFg51P9NCZxK5vsqpvh",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:spf.protection.outlook.com ~all",
      "google-site-verification=GYuY8XAe8jdr6Wr-IFTvC75N3UOWel-PJ3LB55n0f4Q",
      "tiktok-developers-site-verification=C3JxOQdbxqWHFTDQe4NxjsoVILVmkWNz",
      "globalsign-domain-verification=jpcnVg6kuHYyEz5op6ZzxI2E53gePoVqca7RgL0aNq",
      "coda-domain-verification=5a85c362ac0b72f3424ca33c00d23799dce6bdf8ba8f7229063d19b5e44b05c3",
      "3OmNQBavww/twjq0qhOd4N4Iq1nVxlwZIn7++1Ax/cGPh4tRz1V1Vwg1f/TiE2Fno+6l4BykGENz65LMtiRKPQ==",
      "Dynatrace-site-verification=54000376-a605-40b6-955d-7db46b6afc4c__lbfps854cgctskgenckqfr2962",
      "openai-domain-verification=dv-zKMivwPHrBsP7kgvIdS6GaY4",
      "google-site-verification=OuARkQv2V73oYiiZVk88KR1JF5-dQ9Coy1ZRLl6sCsc",
      "ms-domain-verification=28dc05d9-f0d5-48a8-b161-eff7735d41ae",
      "google-site-verification=VtxQaj7j_j013LXYPxlTV644QBxazMYipfG1USdvrOk",
      "v=DKIM1;k=rsa;",
      "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUejllw7R9wJvQ8LoCS5LwXo3xq+ReQWBUMQvktXNmX43LZyDQr0H9dHKuoFsDHwo0nZJk3JAJs610H9dQF+SZyeVL0Pv5Jiq3dSLs/+tyxIBCou20Gy/7b+y6gUvqvMbZWM/fFHfpZgh/3E0vHJXGob/3XxqcW2BtIgxVSf+HTwIDAQAB",
      "yahoo-verification-key=2gylAaYUd1O/rISrcuKML5pponu0SGJJe5E1QavbBNU=",
      "60c96f47dd6a7488b6dd38d5ae33efc370ebc531b96579f91f",
      "atlassian-domain-verification=rPC6tgQBbotGCUJc2KCnOxlbxW4GeR54VPwPc8fVfQpr0y2k2HrSY7PUx+yZZAl1",
      "amazonses:9QIPnjs+UD8ZuYiSqjVTy4qGcBR9TIvB3HD52irZPjk=",
      "ms-domain-verification=2658d552-c7d7-4822-a256-16eb09a6a432",
      "favro-verification=ZZeXG7b1hCYDjKGawUWpxK5LA1IhkTZux_oDE7q5Uml",
      "openai-domain-verification=dv-gHyy52y9q0nsS0u2VTHOjT1o",
      "pendo-domain-verification=b222077a-2e50-4ff3-ad90-fa75f5dca758",
      "anthropic-domain-verification-ydnsfp=iJGHDaz3zCSt83Oek8kGxETGm",
      "logmein-verification-code=a02f93d4-a3af-4666-9eac-1b942a06a775",
      "30d0e455-f274-4c0b-b606-9a835bf5974e.falcon.ea.com",
      "unity-sso-verification=aac6dbce-432e-47c8-b84b-3e2b17bdbbe6",
      "267F68C89F9174C1DE93BE4BD20990BB09014EE6355582AA62F1CA95FC962B2C",
      "jamf-site-verification=S-CTq123ci-Nj6fX_h7xLA",
      "openai-domain-verification=dv-YrfF7OlR2a17O78uKEgzshRW"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc_agg@vali.email,mailto:it-messaging-dmarc-alerts@ea.com; ruf=mailto:it-messaging-dmarc-alerts@ea.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Redwood City, organizationName=Electronic Arts Inc., commonName=starwarssquadrongame.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Nov 24 00:00:00 2025 GMT",
    "notAfter": "Dec 25 23:59:59 2026 GMT",
    "san": [
      "starwarssquadrongame.com",
      "starwarssquadronsgame.us",
      "starwarssquadronsgame.uk",
      "starwarssquadronsgame.space",
      "starwarssquadronsgame.org",
      "starwarssquadronsgame.net",
      "starwarssquadronsgame.jp",
      "starwarssquadronsgame.info",
      "starwarssquadronsgame.fr",
      "starwarssquadronsgame.es",
      "starwarssquadronsgame.email",
      "starwarssquadronsgame.de",
      "starwarssquadronsgame.com.es",
      "starwarssquadronsgame.com.br",
      "starwarssquadronsgame.com",
      "starwarssquadronsgame.co.uk",
      "starwarssquadronsgame.co",
      "starwarssquadronsgame.cm",
      "starwarssquadronsgame.club",
      "starwarssquadronsgame.biz",
      "starwarssquadronsgame.app",
      "starwarssquadrons.games",
      "starwarsquadronsgame.com",
      "starwarsquadrongame.com",
      "starwars-squadronsgame.com",
      "starwars-squadrons-game.com",
      "star-wars-squadrons-game.com",
      "*.starwarssquadronsgame.us",
      "*.starwarssquadronsgame.uk",
      "*.starwarssquadronsgame.space",
      "*.starwarssquadronsgame.org",
      "*.starwarssquadronsgame.net",
      "*.starwarssquadronsgame.jp",
      "*.starwarssquadronsgame.info",
      "*.starwarssquadronsgame.fr",
      "*.starwarssquadronsgame.es",
      "*.starwarssquadronsgame.email",
      "*.starwarssquadronsgame.de",
      "*.starwarssquadronsgame.com.es",
      "*.starwarssquadronsgame.com.br",
      "*.starwarssquadronsgame.com",
      "*.starwarssquadronsgame.co.uk",
      "*.starwarssquadronsgame.co",
      "*.starwarssquadronsgame.cm",
      "*.starwarssquadronsgame.club",
      "*.starwarssquadronsgame.biz",
      "*.starwarssquadronsgame.app",
      "*.starwarssquadrons.games",
      "*.starwarssquadrongame.com",
      "*.starwarsquadronsgame.com",
      "*.starwarsquadrongame.com",
      "*.starwars-squadronsgame.com",
      "*.starwars-squadrons-game.com",
      "*.star-wars-squadrons-game.com",
      "*.simcitybuildit.com",
      "*.itoys.ea.com",
      "*.genesis.ea.com",
      "*.ad.ea.com",
      "eafullcircle.com",
      "www.eafullcircle.com",
      "qa.sst.digitalcodes.ea.com",
      "sst.digitalcodes.ea.com",
      "*.livecontent.pogo.com",
      "*.integration.pogo.com",
      "*.staging.pogo.com",
      "*.orbit.ea.com",
      "supermegabaseball.com",
      "*.slightlymadstudios.com",
      "*.respawn.com",
      "www.dev.gamekit.ea.com",
      "*.glaas.ea.com",
      "*.staging.ea.com",
      "*.myaccount.staging.ea.com",
      "*.preprod.ea.com",
      "*.integration.ea.com",
      "*.glaasts.ea.com",
      "dragonagekeep.com",
      "www.dragonagekeep.com",
      "docs.ea.com",
      "ea.com",
      "*.ea.com",
      "*.linux.ea.com",
      "*.np.gs.ea.com",
      "proxy.novafusion.ea.com",
      "proxy.novafusion.integration.ea.com",
      "*.eainnovation.net",
      "www.designhome.com",
      "designhome.com",
      "*.gamekit.ea.com",
      "covetfashion.com",
      "www.covetfashion.com",
      "*.dcl.ea.com",
      "www.supermegabaseball.com",
      "www.forums.ea.com",
      "*.unreal-ddc.ea.com",
      "*.loyalty.ea.com",
      "tracab.com",
      "www.tracab.com",
      "madden-academy.com",
      "www.madden-academy.com"
    ],
    "days_left": 89,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.209.216.194",
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
  "cookies": [
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
      "origin": "https://sub.ea.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ea.com/"
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
    "source": "crt.sh",
    "count": 1797,
    "notable": [
      "1.dev.gs.ea.com",
      "1.fc.qa.chat.gameservices.ea.com",
      "1.lt.chat.gs.ea.com",
      "10.dev.gs.ea.com",
      "10.fc.qa.chat.gameservices.ea.com",
      "10.lt.chat.gs.ea.com",
      "11.dev.gs.ea.com",
      "11.fc.qa.chat.gameservices.ea.com",
      "11.lt.chat.gs.ea.com",
      "12.dev.gs.ea.com",
      "12.fc.qa.chat.gameservices.ea.com",
      "12.lt.chat.gs.ea.com",
      "13.dev.gs.ea.com",
      "13.fc.qa.chat.gameservices.ea.com",
      "14.dev.gs.ea.com"
    ],
    "sample": [
      "1.dev.gs.ea.com",
      "1.fc.qa.chat.gameservices.ea.com",
      "1.gs.ea.com",
      "1.int.gs.ea.com",
      "1.lt.chat.gs.ea.com",
      "10.dev.gs.ea.com",
      "10.fc.qa.chat.gameservices.ea.com",
      "10.gs.ea.com",
      "10.int.gs.ea.com",
      "10.lt.chat.gs.ea.com",
      "11.dev.gs.ea.com",
      "11.fc.qa.chat.gameservices.ea.com",
      "11.gs.ea.com",
      "11.int.gs.ea.com",
      "11.lt.chat.gs.ea.com",
      "12.dev.gs.ea.com",
      "12.fc.qa.chat.gameservices.ea.com",
      "12.gs.ea.com",
      "12.int.gs.ea.com",
      "12.lt.chat.gs.ea.com"
    ],
    "dangling": [
      "1.dev.gs.ea.com",
      "1.fc.qa.chat.gameservices.ea.com",
      "1.lt.chat.gs.ea.com",
      "10.dev.gs.ea.com",
      "10.fc.qa.chat.gameservices.ea.com"
    ]
  },
  "apex_txt": [
    "apple-domain-verification=AYQE6OxMih12JCzk",
    "parsec-domain-verification=td_2PekalqDxqm3NIcvbo3Megt72X9",
    "google-site-verification=HYdRtN3xk_TxaVDfhAVQb-Qbav7wj57E01Pci8x3oOg",
    "adobe-sign-verification=c3b24a9842e8e22172e2568873e4ed3b",
    "ms-domain-verification=3e25dee7-ae46-448e-b9b9-20a6490f7af8"
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
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 10121077189511301222740088265264893005,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311530130603550407130c526564776f6f642043697479311d301b060355040a1314456c656374726f6e6963204172747320496e632e3121301f0603550403131873746172776172737371756164726f6e67616d652e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20251124000000",
      "not_after": "20261225235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a23-209-216-194.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.ea.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=15768000",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
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
    "alt_svc": "h3=\":443\"; ma=93600",
    "cdn": [
      "Akamai"
    ]
  },
  "elapsed_s": 9.8,
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
