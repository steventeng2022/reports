# Security Audit Report — ea.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ea.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ea.com |
| Test date | 2026-09-26 17:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 5, Info: 16)

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
| 20 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 21 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |

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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=W_cWHGmP5RqmA9hYnm8inTTb9Sau7q1Ro911CH4SrZ8; google-site-verification=GYuY8XAe8jdr6Wr-IFTvC75N3UOWel-PJ3LB55n0f4Q; atlassian-domain-verification=rPC6tgQBbotGCUJc2KCnOxlbxW4GeR54VPwPc8fVfQpr0y2k2H
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 20. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of ea.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 21. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but ea.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

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
      "a1-164.akam.net.",
      "a7-66.akam.net.",
      "a6-65.akam.net.",
      "a8-67.akam.net.",
      "a13-67.akam.net.",
      "a4-64.akam.net."
    ],
    "spf": [
      "google-site-verification=W_cWHGmP5RqmA9hYnm8inTTb9Sau7q1Ro911CH4SrZ8",
      "google-site-verification=GYuY8XAe8jdr6Wr-IFTvC75N3UOWel-PJ3LB55n0f4Q",
      "v=DKIM1;k=rsa;",
      "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUejllw7R9wJvQ8LoCS5LwXo3xq+ReQWBUMQvktXNmX43LZyDQr0H9dHKuoFsDHwo0nZJk3JAJs610H9dQF+SZyeVL0Pv5Jiq3dSLs/+tyxIBCou20Gy/7b+y6gUvqvMbZWM/fFHfpZgh/3E0vHJXGob/3XxqcW2BtIgxVSf+HTwIDAQAB",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:spf.protection.outlook.com ~all",
      "atlassian-domain-verification=rPC6tgQBbotGCUJc2KCnOxlbxW4GeR54VPwPc8fVfQpr0y2k2HrSY7PUx+yZZAl1",
      "adobe-idp-site-verification=b36e2eb4-d986-4903-a5be-15e3651396cf",
      "MS=ms19667016",
      "amazonses:f11tLfH2vr9OwsWpUEXnb+wXe8KNcen1j3Lk5fK4W7U=",
      "google-site-verification=JPqUmrL51cf3BGW7dM_RP70SaOhgCQpfVmfEWE4JWS0",
      "work-accounts-domain-verification=yeSmLL1AKrKom6NYUJRpBGBjrmRkCD",
      "docker-verification=4bfce2f1-7d0f-474e-a43b-d60d18b35182",
      "QfGw4p+QlBkLTkHaJRQrTAHpN+ZgoZENi4uAnKBoQVVKGMBBhCzqeTpmndH2fHvajdi9FWSCrdQrPwQ7hzZMDA==",
      "openai-domain-verification=dv-YrfF7OlR2a17O78uKEgzshRW",
      "yahoo-verification-key=2gylAaYUd1O/rISrcuKML5pponu0SGJJe5E1QavbBNU=",
      "lookingglassweb.azurewebsites.net",
      "tiktok-developers-site-verification=VcYwjcEIoOmPFODSYEQjCUP09jElnNkn",
      "mongodb-site-verification=cPx4xoyitTn3W8MmDPht4i7jYkP8v55b",
      "Dynatrace-site-verification=54000376-a605-40b6-955d-7db46b6afc4c__lbfps854cgctskgenckqfr2962",
      "amazonses:9QIPnjs+UD8ZuYiSqjVTy4qGcBR9TIvB3HD52irZPjk=",
      "google-site-verification=dSC8gq7vptNeGVIDEpGQZ0xE8s-5BBIbc1r6R3_PwT0",
      "ms-domain-verification=28dc05d9-f0d5-48a8-b161-eff7735d41ae",
      "cisco-ci-domain-verification=4cb82531e58e0b3c12afb359f5142eb4d461e0e589eefa3603a9af7317a8afd2",
      "openai-domain-verification=dv-zKMivwPHrBsP7kgvIdS6GaY4",
      "logmein-verification-code=a02f93d4-a3af-4666-9eac-1b942a06a775",
      "openai-domain-verification=dv-gHyy52y9q0nsS0u2VTHOjT1o",
      "google-site-verification=HYdRtN3xk_TxaVDfhAVQb-Qbav7wj57E01Pci8x3oOg",
      "adobe-sign-verification=c3b24a9842e8e22172e2568873e4ed3b",
      "favro-verification=ZZeXG7b1hCYDjKGawUWpxK5LA1IhkTZux_oDE7q5Uml",
      "anthropic-domain-verification-g53wq8=Hgm9Dc1mrdVQjGxnZWm4CSgri",
      "01E6D34C64F24201EE75D6BB52FD49ECA8E7F05E57CFC5D9963DFE28F5DD793B",
      "jamf-site-verification=S-CTq123ci-Nj6fX_h7xLA",
      "snowflake-verification=71ba1450-019f-1000-8718-000000000413",
      "shopify-verification-code=oarXm8VVyw5BycTVUZS53HSydl24Ba",
      "ms-domain-verification=3e25dee7-ae46-448e-b9b9-20a6490f7af8",
      "atlassian-domain-verification=TcMmJBl8jkffKRnLX0s82TVPAOBmzFE8N1xCvCg42ehCFfU8nxO1rMZcSCLdiIMh",
      "tiktok-developers-site-verification=gZsAdTrtYEO38BFg51P9NCZxK5vsqpvh",
      "amazonses:SMeDjsim2TRE1HOX7bQmJJhBjV2DZPdakNXVtC1U5QA=",
      "unity-sso-verification=aac6dbce-432e-47c8-b84b-3e2b17bdbbe6",
      "apple-domain-verification=AYQE6OxMih12JCzk",
      "60c96f47dd6a7488b6dd38d5ae33efc370ebc531b96579f91f",
      "267F68C89F9174C1DE93BE4BD20990BB09014EE6355582AA62F1CA95FC962B2C",
      "anthropic-domain-verification-ydnsfp=iJGHDaz3zCSt83Oek8kGxETGm",
      "amazonses:mgCkNYnAkmnZtXK6zLrZW+THRSUyJZGJnSOBdj+isYU=",
      "amazonses:h4cXsZhHgq6fK4DGoUQgriYwSeE6hO5aJ+h6wHnx/fk=",
      "v=DMARC1;",
      "p=none;",
      "fo=1;",
      "rua=mailto:yesmail@rua.agari.com;",
      "ruf=mailto:yesmail@ruf.agari.com",
      "tiktok-developers-site-verification=UWDwy70DCmMmCerrJX6oV1pRGABPapRe",
      "ms-domain-verification=2658d552-c7d7-4822-a256-16eb09a6a432",
      "3OmNQBavww/twjq0qhOd4N4Iq1nVxlwZIn7++1Ax/cGPh4tRz1V1Vwg1f/TiE2Fno+6l4BykGENz65LMtiRKPQ==",
      "google-site-verification=VtxQaj7j_j013LXYPxlTV644QBxazMYipfG1USdvrOk",
      "globalsign-domain-verification=jpcnVg6kuHYyEz5op6ZzxI2E53gePoVqca7RgL0aNq",
      "tiktok-developers-site-verification=C3JxOQdbxqWHFTDQe4NxjsoVILVmkWNz",
      "parsec-domain-verification=td_2PekalqDxqm3NIcvbo3Megt72X9",
      "Console2714e2e7-3fa3-4b34-8693-c09b1d9986c6",
      "google-site-verification=T8NmTlNnB0xPkycfop5hMmOAVQSivlmA4d8Y7--2x6U",
      "facebook-domain-verification=oq80s5pdyo1d8huizochkuyscyewf2",
      "smartsheet-site-validation=2s81-L1kix0MAeJQmj44rEehwVlCUIYV",
      "AagMut9FoA4ka4DYvu3QvUa5FRJCN4esFVQ3RG6RdGAjA8hTAlxLXme7sSHZnFDNX7XAPe5BIIbg1G23k2oVow==",
      "google-site-verification=QO6a-pP_siI7I6KAzi6Lj_GMmKik10qnGpIa-qDiaSs",
      "google-site-verification=OuARkQv2V73oYiiZVk88KR1JF5-dQ9Coy1ZRLl6sCsc",
      "google-site-verification=069b0lSxMIobzf7rJTBnXqb1KDTmfFhsJMm8mP9xnBU",
      "coda-domain-verification=5a85c362ac0b72f3424ca33c00d23799dce6bdf8ba8f7229063d19b5e44b05c3",
      "30d0e455-f274-4c0b-b606-9a835bf5974e.falcon.ea.com",
      "lovable_verification=wZkgBHNGXK1sMxUCtqNt",
      "pendo-domain-verification=b222077a-2e50-4ff3-ad90-fa75f5dca758"
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
    "days_left": 90,
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=W_cWHGmP5RqmA9hYnm8inTTb9Sau7q1Ro911CH4SrZ8",
    "google-site-verification=GYuY8XAe8jdr6Wr-IFTvC75N3UOWel-PJ3LB55n0f4Q",
    "atlassian-domain-verification=rPC6tgQBbotGCUJc2KCnOxlbxW4GeR54VPwPc8fVfQpr0y2k2H",
    "adobe-idp-site-verification=b36e2eb4-d986-4903-a5be-15e3651396cf",
    "google-site-verification=JPqUmrL51cf3BGW7dM_RP70SaOhgCQpfVmfEWE4JWS0"
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
      "aia_ocsp": null
    }
  },
  "elapsed_s": 7.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
