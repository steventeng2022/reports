# Security Audit Report — apple.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://apple.com/ |
| Bug bounty program | Apple |
| Listed scope domain | apple.com |
| Test date | 2026-09-27 02:18 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **25** (High: 0, Medium: 0, Low: 7, Info: 18)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 17 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 18 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 19 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |
| 20 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |
| 21 | low | I22 | Hidden redirect parameter surface (canonical 404 retains parameter) (no open redirect) | CWE-538 |
| 22 | low | S1 | First-party branded subdomain surface (live beta/news/support/help origins) (not dangling) | CWE-916 |
| 23 | info | S1 | OAuth handoff discloses client_id, redirect_uri and broad scope | CWE-200 |
| 24 | info | S1 | Erroring first-party subdomains (account 500, mobile/oauth 400 AkamaiGHost) | CWE-200 |
| 25 | info | S1 | images.apple.com serves the full homepage (Akamai TCP_REFRESH_MISS, 254,242 B) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.apple.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=L5kkMdiFI8npvb6KlHui84fJaCw5G64DWhaDRIAT4_c; miro-verification=2494d255c4c50b1e521650a0659cbf3fa08b0072; Dynatrace-site-verification=7d881a7c-c13f-4146-9d27-2731459e2509__iqls0105tagglc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.apple.com/ocsp03-apevsecc1g101 -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 9 disallow path(s), e.g. /*shop/browse/overlay/*, /*shop/iphone/payments/overlay/*, /cn/*/aow/*, /tmall*, /*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 17.253.144.10 carries PTR apple.com.gy., apple.com.tt., vipd-healthcheck.a01.3banana.com., itunespartner.apple.com., apple.fr., apple.it., livepage.apple.com., apple.ca., apple.de., apple.com.uy., apple.com.mx., firewire.apple.com., icloud.com., guide.apple.com., apple.com., apple.com.au., apple.com.do., podcast.apple.com., aperturetrialbuy.apple.com., apple.es., apple.com.ai., apple.com.py., iphone.apple.com., applecomputer.co.kr., apple.com.pe., applescript.apple.com., advertising.apple.com., safaricampaign.apple., apple.com.bo., apple.co.uk., apple.com.hn., asia.apple.com., world-any.aaplimg.com., iworktrialbuy.apple.com., apple.com.cn., apple.com.lk., apple.nl., appstore.com., shake.apple.com., squeakytoytrainingcamp.com., apple.com.sg., apple.com.my., www.brkgls.com., apple.com.pa., applejava.apple.com., brkgls.com., seminars.apple.com., apple.com.co. for apple.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on apple.com lists 862 <loc> URL(s); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 17. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on apple.com identify the edge as Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 18. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of apple.com is http://ocsp.apple.com/ocsp03-apevsecc1g101; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 19. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of apple.com discloses a 1-hop fronting chain (http/1.1 twtpe2-edge-fx-011.ts.apple.com (acdn/331.16659)); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

### 20. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of apple.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.
### 21. [LOW] Hidden redirect parameter surface (canonical 404 retains parameter) (no open redirect) (`I22`)

- **CWE:** CWE-538
- **Detail:** /r?url=, /r?u=, /go?url=, /go?u= -> 301 to canonical /r/?url= and /go/?url= (param retained in Location, 267-270 B) then 404 (111,090 B Apple 404 page). The token survives the redirect chain but no handler consumes it - no open redirect (probe-r35redirects).
- **Recommendation:** Document or consume the retained parameter on the canonical 404.

### 22. [LOW] First-party branded subdomain surface (live beta/news/support/help origins) (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** beta.apple.com = 200 (15,318 B, Apple origin); news.apple.com = 200 (7,426 B, AppleHttpServer/<sha> origin); help.apple.com = 200 (178 B); support.apple.com = 200 (130,088 B); files/portal.apple.com = 403 (207/548 B); shop/store 301 -> /store. All first-party, no dangling CDN signature (probe-r35dsubs).
- **Recommendation:** Keep these first-party origins documented; watch the news AppleHttpServer origin.

### 23. [INFO] OAuth handoff discloses client_id, redirect_uri and broad scope (`S1`)

- **CWE:** CWE-200
- **Detail:** upload.apple.com = 302 -> idmsac.apple.com OAuth authorize with client_id=9lhahlaflt4a4nlce2fuhsiix8wlfr, redirect_uri=upload.apple.com/__login, scope=openid profile email phone dsid adsid accountname roles groups extended_profile offline_access. Standard first-party IdP, but the scope list is broad (phone, offline_access).
- **Recommendation:** Consider trimming the disclosed scope on public handoffs.

### 24. [INFO] Erroring first-party subdomains (account 500, mobile/oauth 400 AkamaiGHost) (`S1`)

- **CWE:** CWE-200
- **Detail:** account.apple.com = 500 (0 B); mobile.apple.com = 400 (650 B); oauth.apple.com = 400 (312 B, AkamaiGHost). Transient edge errors observed once each during the sweep; first-party hosts.
- **Recommendation:** Recheck at next audit; treat as transient unless repeated.

### 25. [INFO] images.apple.com serves the full homepage (Akamai TCP_REFRESH_MISS, 254,242 B) (`S1`)

- **CWE:** CWE-200
- **Detail:** images.apple.com = 200 (254,242 B, AkamaiGHost TCP_REFRESH_MISS from a23-46-63-159) - the asset host returns the full www homepage document, suggesting a vhost fallback configuration.
- **Recommendation:** Confirm the images host vhost mapping with the origin team.

## Active re-verification (2026-09-30, agent-aggressive)

- **I22 x1:** /r?{url,u}, /go?{url,u} -> 301 canonical /r/ /go/ -> 404 (111,090 B), param retained, no handler (probe-r35redirects).
- **S1 x4:** beta 200 (15,318 B), news 200 (7,426 B AppleHttpServer), help 200 (178 B), support 200 (130,088 B), files/portal 403, shop/store 301 -> /store; upload 302 -> idmsac OAuth (client_id disclosed); account 500, mobile/oauth 400 (AkamaiGHost); images 200 (254,242 B full homepage) (probe-r35dsubs).

## Evidence (raw response observations)

```json
{
  "domain": "apple.com",
  "dns": {
    "a": [
      "17.253.144.10"
    ],
    "aaaa": [
      "2620:149:af0::10"
    ],
    "cname": null,
    "mx": [
      "mx-in-rn.apple.com (pref 20)",
      "mx-in-vib.apple.com (pref 20)",
      "mx-in-sg.apple.com (pref 20)",
      "mx-in.g.apple.com (pref 10)",
      "mx-in-ma.apple.com (pref 20)",
      "mx-in-hfd.apple.com (pref 20)"
    ],
    "ns": [
      "d.ns.apple.com.",
      "b.ns.apple.com.",
      "c.ns.apple.com.",
      "a.ns.apple.com."
    ],
    "caa": [
      "0 iodef \"mailto:contact_pki@apple.com\"",
      "0 issue \"pki.apple.com\"",
      "0 issuewild \"pki.apple.com\""
    ],
    "spf": [
      "google-site-verification=L5kkMdiFI8npvb6KlHui84fJaCw5G64DWhaDRIAT4_c",
      "miro-verification=2494d255c4c50b1e521650a0659cbf3fa08b0072",
      "v=spf1 include:_spf.apple.com include:_spf-txn.apple.com ~all",
      "Dynatrace-site-verification=7d881a7c-c13f-4146-9d27-2731459e2509__iqls0105tagglcsaul0m16ibrf",
      "ValidationTokenValue=77a4a6de-da14-449c-83c4-85366e0f55f9",
      "facebook-domain-verification=n6cqjfucq6plswmtfbwnbbeu1qiq3v",
      "yahoo-verification-key=Ay+djyw0qWQgXKWGA/jstjYryTMrKb+PBXI5l8u5/jw=",
      "google-site-verification=zBSq1mG5ssu2If-C17UAz_MzSZDcx03MVxmeDwMNc5w",
      "atlassian-domain-verification=qZD4TfnCAoAjCFQgafhoKQpOs9tviekNK4wYE4a5eK3XoRP06hXAvEp8SLU0v7fI",
      "_eht2v8yfz1agpq7o4zdkkz3k0k86fyr",
      "atlassian-domain-verification=mLabq99iaT8kquJechF6l31FAYoNUe3WB7tLpLFUiUYVJCse9SKq83hOJzFkwqrh",
      "_khcec23xgc5b2lb981hup1csjb4cdnz",
      "lucidlink-verification=SCDW9V44GJHAVXKFS6ZY6EZ2YR",
      "cisco-ci-domain-verification=6f3bfb849796a518061f8e8c4356f687a138502d86db742791685059176547dd",
      "apple-domain-verification=X5Jt76bn3Dnmgzjj",
      "adobe-idp-site-verification=6bd5e74c-a3a0-4781-b2e1-e95399b5e11c",
      "json:eyJ3aHkiOiJUaGlzIGlzIHRvIHRydW5jYXRlIFVEUCByZXNwb25zZXMgZm9yIFRYVCBxdWVyaWVzIHRvIGFwcGxlLmNvbSIsInBhZGRpbmciOiJxdWFoMGVpamFhNGVlajh0aWVkYWlnaG9jZWljaGFlOGVUb3ppZTVmdTVhaFRoMldlaU00aWsyaHVxdThpZXBoaWVxdW9oc2hlaXBhZWdoOUthZWw3b2NoaWVuZ2llem9lc2g1In0K",
      "77a4a6de-da14-449c-83c4-85366e0f55f9",
      "google-site-verification=8M6XjQCzydT62jk8HY3VXPAG-nKDllTRV-JpA3-Ktyw",
      "json:eyJ3aHkiOiJUaGlzIGlzIHRvIHRydW5jYXRlIFVEUCByZXNwb25zZXMgZm9yIFRYVCBxdWVyaWVzIHRvIGFwcGxlLmNvbSIsInBhZGRpbmciOiJpZW4wYWVHaGF0aG9oNmhhaHZpZWphaTNlYXkwYWh2YWhjaGFocXVhZWxlZTBZdWw0cGhpZXRoMHNvNXZpZXllZWNvaDRpZThzaGVlcGllVDNwYWVjaGVpVjZqb2h3aWVwaG82In0K",
      "cerner-client-id=22dd1d8a-5e8b-4e1e-80ef-39bcdfd42798",
      "cerner-client-id=ce3abf18-ee87-43b9-9927-9eb24b4bac4a",
      "webexdomainverification.8C462=b728ec3f-dfc9-42f9-92cb-9ba8853cbee8"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; sp=reject; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "businessCategory=Private Organization, jurisdictionCountryName=US, jurisdictionStateOrProvinceName=California, serialNumber=C0806592, countryName=US, stateOrProvinceName=California, localityName=Cupertino, organizationName=Apple Inc., commonName=apple.com",
    "issuer": "countryName=US, organizationName=Apple Inc., commonName=Apple Public EV Server ECC CA 1 - G1",
    "notBefore": "Aug 13 16:20:01 2026 GMT",
    "notAfter": "Nov  5 20:55:13 2026 GMT",
    "san": [
      "apple.com"
    ],
    "days_left": 39,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "17.253.144.10",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.apple.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.apple.com/"
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
    "google-site-verification=L5kkMdiFI8npvb6KlHui84fJaCw5G64DWhaDRIAT4_c",
    "miro-verification=2494d255c4c50b1e521650a0659cbf3fa08b0072",
    "Dynatrace-site-verification=7d881a7c-c13f-4146-9d27-2731459e2509__iqls0105tagglc",
    "ValidationTokenValue=77a4a6de-da14-449c-83c4-85366e0f55f9",
    "facebook-domain-verification=n6cqjfucq6plswmtfbwnbbeu1qiq3v"
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
      "aia_ocsp": "http://ocsp.apple.com/ocsp03-apevsecc1g101",
      "serial": 112470689249836118839205980247951250564,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.apple.com/apevsecc1g1.crl"
      ],
      "san": [
        "apple.com"
      ],
      "subject_dn": "311d301b060355040f0c1450726976617465204f7267616e697a6174696f6e31133011060b2b0601040182373c02010313025553311b3019060b2b0601040182373c0201020c0a43616c69666f726e69613111300f060355040513084330383036353932310b30090603550406130255533113301106035504080c0a43616c69666f726e69613112301006035504070c09437570657274696e6f31133011060355040a0c0a4170706c6520496e632e3112301006035504030c096170706c652e636f6d",
      "issuer_dn": "310b300906035504061302555331133011060355040a130a4170706c6520496e632e312d302b060355040313244170706c65205075626c696320455620536572766572204543432043412031202d204731",
      "not_before": "20260813162001",
      "not_after": "20261105205513"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/*shop/browse/overlay/*",
      "/*shop/iphone/payments/overlay/*",
      "/cn/*/aow/*",
      "/tmall*",
      "/*",
      "/*",
      "/*",
      "/*",
      "/*"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "apple.com.gy.",
      "apple.com.tt.",
      "vipd-healthcheck.a01.3banana.com.",
      "itunespartner.apple.com.",
      "apple.fr.",
      "apple.it.",
      "livepage.apple.com.",
      "apple.ca.",
      "apple.de.",
      "apple.com.uy.",
      "apple.com.mx.",
      "firewire.apple.com.",
      "icloud.com.",
      "guide.apple.com.",
      "apple.com.",
      "apple.com.au.",
      "apple.com.do.",
      "podcast.apple.com.",
      "aperturetrialbuy.apple.com.",
      "apple.es.",
      "apple.com.ai.",
      "apple.com.py.",
      "iphone.apple.com.",
      "applecomputer.co.kr.",
      "apple.com.pe.",
      "applescript.apple.com.",
      "advertising.apple.com.",
      "safaricampaign.apple.",
      "apple.com.bo.",
      "apple.co.uk.",
      "apple.com.hn.",
      "asia.apple.com.",
      "world-any.aaplimg.com.",
      "iworktrialbuy.apple.com.",
      "apple.com.cn.",
      "apple.com.lk.",
      "apple.nl.",
      "appstore.com.",
      "shake.apple.com.",
      "squeakytoytrainingcamp.com.",
      "apple.com.sg.",
      "apple.com.my.",
      "www.brkgls.com.",
      "apple.com.pa.",
      "applejava.apple.com.",
      "brkgls.com.",
      "seminars.apple.com.",
      "apple.com.co."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.apple.com/",
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
    "sitemap": {
      "urls": 862,
      "indexes": 0
    },
    "crl": {
      "url": "http://crl.apple.com/apevsecc1g1.crl",
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
      "Fastly"
    ]
  },
  "x17": {
    "ocsp_http": "http://ocsp.apple.com/ocsp03-apevsecc1g101",
    "via": "http/1.1 twtpe2-edge-fx-011.ts.apple.com (acdn/331.16659)"
  },
  "elapsed_s": 5.0,
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
