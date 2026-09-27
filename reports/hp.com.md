# Security Audit Report — hp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hp.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hp.com |
| Test date | 2026-09-27 02:33 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 3, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 8 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 9 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 10 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 11 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 14 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 15 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 16 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 17 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 18 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
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
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 7. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 8. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): us. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 9. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 10. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 11. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: tiktok-domain-verification=c31cb3ab1359c3755fc548a1a60875056dff634430d936d99b825; goodnotes-verification=08e7496e-47ad-4e16-8b9a-12c40efbe0f9; google-site-verification=ior6EHEPCvMGbBIF1Cfzg3-yTDw30PaIbETytGrl1zY
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but hp.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 13.227.47.69 carries PTR server-13-227-47-69.mci50.r.cloudfront.net. for hp.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 14. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for hp.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 15. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on hp.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of hp.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 16. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on hp.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 17. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of hp.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 18. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of hp.com discloses a 1-hop fronting chain (1.1 91497c7d9eb98069bdcff6f49956c240.cloudfront.net (CloudFront)); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

## Evidence (raw response observations)

```json
{
  "domain": "hp.com",
  "dns": {
    "a": [
      "13.227.47.69",
      "13.227.47.47",
      "13.227.47.22",
      "13.227.47.6"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "us-smtp-inbound-1.mimecast.com (pref 10)"
    ],
    "ns": [
      "ns2.hp.com.",
      "ns6.hp.com.",
      "ns4.hp.com.",
      "ns1.hp.com.",
      "ns3.hp.com.",
      "ns5.hp.com."
    ],
    "caa": [],
    "spf": [
      "7155-7871-A6E8-AEB1-5764-4DE3-D4DD-6680",
      "tiktok-domain-verification=c31cb3ab1359c3755fc548a1a60875056dff634430d936d99b825643f08293c4",
      "02.14.2024",
      "SFMC-f7skz24QEr_YzGdBqMHR3sC2xGZPNQ3mZdXDFFow",
      "SFMC-VXyPhU37JRfzHa1B_-XfXzHjl2WKI7af1rdKH-wR",
      "goodnotes-verification=08e7496e-47ad-4e16-8b9a-12c40efbe0f9",
      "fastly-domain-delegation-ndopinwe32-10142022",
      "google-site-verification=ior6EHEPCvMGbBIF1Cfzg3-yTDw30PaIbETytGrl1zY",
      "shopify-verification-code=U5Mvz3J5IScCrDvvcy49c7chv8Iwxp",
      "google-site-verification=lf2HoI19pw29dSNCWe1ex0zlgiGiMSUZjRWjW61SLXk",
      "google-site-verification=GdVvq6F-s2Vr-eD8eeZeo11J1HXnWdA2ZNM_M_IivjY",
      "SFMC-MNg49ZTRiJXS6s5M39xVpTy1s_E-1IHXs9eMp9TV",
      "paloaltonetworks-site-verification=1490b1ee9f50f41d487a017ed98225cd2f0bcbed857fa5841aa276a5a009b604",
      "hpe-greenlake-domain-verification=7151716b744d3467684e427773486a5244794c3172676333326e753537787941",
      "google-site-verification=ZKYzB8FoSfCdYZzesihRSd5OsBfrtDOvG6zrqYcMcd0",
      "",
      "google-site-verification=iBm5BtEQIPx_1KICdm-iKrhED8pwZmS12JcztEGkEEw\"\"\"",
      "_ndgc16081saphv6ayms33rbsvl6rj68",
      "SFMC-TkI3rEvFMq3uO7c3713TrP-cg1S7j0K0iKyNVXIY",
      "airtable-verification=fd35e3a14eafa013a4ef8ec307159c57",
      "canva-site-verification=phuz1k47EJb7b9wGXtCeYw",
      "atlassian-domain-verification=cbeZ9ZZ8XZI9vcf3e6CYWsA3pQ/6Xfc2mSUGdHuK5bWhjzVD0ksLTbFdabq//Sd5",
      "Dynatrace-site-verification=fb0772f5-465e-4c26-9c6e-de883a321a31__ko3f16m3vui8oi46qls2l305im",
      "teamviewer-sso-verification=9a8bdacd256d426aadef7c9435cc05f7",
      "_t0t2hodeyznakvwlx7hkbim4oojp151",
      "SFMC-Gj1r4WT7h7LuH9CgR-ATrs4dQiyHzeRW5mkk_qg9",
      "gem-domain-verification=BTTGt2-RR8Zy86kgA6dRzh",
      "atlassian-domain-verification=mjss59VLEmjHpiASn3FUy/Hfb/9QbLAAOR9fiqjavAJ6O1uCyNnChSTbNAxo7IIS",
      "perplexity-ai-domain-verification-9026ms=OwUIgCvAepDBJvWzS6xNO3zPX",
      "bv-domain-verification=ca416dec3e1078035e8f94141e8542a1207d3415febb81cdecc6f69d491ee03c",
      "docker-verification=ad83199a-7103-4f01-8acf-41979b12ba00",
      "SFMC-ZWQ1KX6NcnbWgSDBdMcM5hev9zt7KIW2ujakv25u",
      "SFMC-aJMC0Gi9MPXTz-l4Iv3LtRXfhaeOB0OCsGwNXkzM",
      "atlassian-domain-verification=aD0fVXowmsHVk7AN3xQWoTk3fWQjFOAolW1g5Ae492aMfXofVIdEeASIKtjKtOjn",
      "google-site-verification=K295XYTk_JOny2cGYgQiv5OBkqX-vsPbflRWCajmZmQ",
      "pendo-domain-verification=f79d1d3d-277a-4a70-982c-677c77a2f011",
      "google-site-verification=ajtjung8rHe1-msfHMrttoZdDlZeeoWJNpQ5jNZcqfo",
      "SFMC-z90jhAqnCFzmMAy46Qo1vy13u6YlOQ4afVWEPZmS",
      "IQI2xT+r6hj2PuJ171J02xOMMXSUHl4I2VJ5a4CB2OsyfPJkfHXHbmJ5e2Ee6kbNjJQsERvcm3d4IeS2e7xPPQ==",
      "teamviewer-sso-verification=14e16276afc843e58d056742e9f89d26",
      "asv=3ac585f916271e3615c45c5cc1c446af",
      "facebook-domain-verification=1f6jis8ngyl6xhtopb196nk2jzb6wm",
      "SFMC-CrddN9mLDmj3nCgVdj6F1xvJWHcDiUha4ypozOYM",
      "launchdarkly-domain-verification=c190690f-6cf2-4084-9ea4-ddbeebcebc80",
      "SFMC-gC-INJ9awb38orE0daCKtYQOdTzA26V3zBYVruOP",
      "google-site-verification=SYstg4r0qao99bYV9-4uWYGTHLSIL3Py60GZvR_OJ1c",
      "google-site-verification=7CCNFPK5u6aSDkOkTOxz_yOePZI8_thHJnaJl6EtSwk",
      "perplexity-ai-domain-verification-9026ms=pYLmCXhTHCODhZSFIiyoguCNL",
      "v=spf1 mx include:_spf.hp.com include:_spf.salesforce.com include:us._netblocks.mimecast.com",
      " include:spf.protection.outlook.com include:standardregisterSPF.smtp.com ip4:205.219.85.237 ip4:74.209.251.23 ip4:198.245.88.159 ip4:198.245.88.160 ip4:198.245.88.161 ip4:198.245.88.162 ~all",
      "adobe-sign-verification=8d7c98c65d9a78aa4fe83e40ac618269",
      "MS=ms38857149",
      "google-site-verification=N-C2RScU5fi3a4_9J7hYoQhoL9H566pkx6gM8PI6Jqo",
      "liveramp-site-verification=LpuGIkdkGN7Dr495prdDxPoD0K4Y8zox5B40KiQVq08",
      "hcp-domain-verification=d172505ee1cb87d71e2f402ab1e6123f01c858917022925ee9fe25ce1ea6a398",
      "C6ekla14kZc9ySs2tWLx5+qoT3uFAcPKfM9z8SnOjKPxduvwIiHCJI75yVt8cOynDwTRpNGAoAu7WBKTky3QhQ==",
      "mongodb-site-verification=NNt4TMRanOtPk2qCvhWpTMXpY8SOb7BO",
      "google-site-verification:2kiyv1SjebKUcEmaJ4QtapQe2EcbqPcYmhiJ-XJMZsY"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=none; pct=100; fo=1; rua=mailto:l1rcsnp0@ag.dmarcian.com; ruf=mailto:l1rcsnp0@fr.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Palo Alto, organizationName=HP Inc, commonName=hpcom-pro-domain-cloudfront-13.hpcloud.hp.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jul 16 00:00:00 2026 GMT",
    "notAfter": "Jan 30 23:59:59 2027 GMT",
    "san": [
      "hpcom-pro-domain-cloudfront-13.hpcloud.hp.com",
      "wirelesscolorprinters.com",
      "www3hp.com",
      "www.wirelesscolorprinters.com",
      "webprintsmart.com",
      "wwwhpdirect.com",
      "www.webprintsmart.com",
      "www.wwwhpdirect.com",
      "wwwhp.com",
      "www.twitterhp.com",
      "wwwhpshopping.com",
      "www.www3hp.com",
      "www.wwwhp.com",
      "www.touchsmartprinter.com",
      "twitterhp.com",
      "www.touchsmartprinters.com",
      "touchsmartprinters.com",
      "www.wwwhpshopping.com",
      "touchsmartprinter.com",
      "www.hp.ca",
      "hp.be",
      "hp.com.nf",
      "www.hp.co.ke",
      "hp.co.th",
      "www.hp.co.kr",
      "hp.co.cr",
      "www.hp.cl",
      "www.hp.com.kn",
      "www.hp.co",
      "hp.co.kr",
      "hp.com.jm",
      "www.hp.cg",
      "www.hp.com.my",
      "www.hp.co.je",
      "hp.co.il",
      "h30167.www3.hp.com",
      "www.hp.co.ve",
      "hp.co.uk",
      "www.hp.co.mz",
      "www.hp.co.at",
      "www.hp.com.mx",
      "hp.co.id",
      "www.hp.com.mu",
      "www.www8-hp.com",
      "hp.com.my",
      "hp.com.mx",
      "www.hp.co.nz",
      "h20545.www2.hp.com",
      "www.hp.com.jm",
      "hp.com.mu",
      "hp.co.ug",
      "hp.co.tz",
      "www.hp.com.nf",
      "hp.am",
      "www.hp.be",
      "www.hp.co.rs",
      "www.hp.co.uk",
      "hp.com.pk",
      "hp.co.rs",
      "hp.com.pe",
      "www.hp.co.id",
      "www.hp.com.hn",
      "hp.com.pa",
      "www.hp.com.hr",
      "www.hp.com.lv",
      "hp.co.je",
      "www.hp.co.ug",
      "hp.co.mz",
      "hp.com.hr",
      "hp.com.lv",
      "www.hp.co.za",
      "www8-hp.com",
      "hp.co.ve",
      "hp.com.hn",
      "hp.co.at",
      "www.hp.am",
      "hp.co.za",
      "hp.com.hk",
      "www.hp.co.il",
      "hp.cl",
      "hp.cg",
      "www.hp.com.pa",
      "hp.ca",
      "www.hp.co.cr",
      "www.hp.co.th",
      "hp.co.ke",
      "hp.co.nz",
      "www.hp.co.tz",
      "www.hp.com.hk",
      "hp.com.kn",
      "www.hp.com.pe",
      "www.hp.com.pk",
      "hp.co",
      "hp.com",
      "www.hp.com",
      "123.hp.com",
      "www.123.hp.com"
    ],
    "days_left": 125,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "13.227.47.69",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.hp.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://hp.com/"
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
    "tiktok-domain-verification=c31cb3ab1359c3755fc548a1a60875056dff634430d936d99b825",
    "goodnotes-verification=08e7496e-47ad-4e16-8b9a-12c40efbe0f9",
    "google-site-verification=ior6EHEPCvMGbBIF1Cfzg3-yTDw30PaIbETytGrl1zY",
    "shopify-verification-code=U5Mvz3J5IScCrDvvcy49c7chv8Iwxp",
    "google-site-verification=lf2HoI19pw29dSNCWe1ex0zlgiGiMSUZjRWjW61SLXk"
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
      "serial": 10488696391004016747559608389525557612,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "san": [
        "hpcom-pro-domain-cloudfront-13.hpcloud.hp.com",
        "wirelesscolorprinters.com",
        "www3hp.com",
        "www.wirelesscolorprinters.com",
        "webprintsmart.com",
        "wwwhpdirect.com",
        "www.webprintsmart.com",
        "www.wwwhpdirect.com",
        "wwwhp.com",
        "www.twitterhp.com",
        "wwwhpshopping.com",
        "www.www3hp.com",
        "www.wwwhp.com",
        "www.touchsmartprinter.com",
        "twitterhp.com",
        "www.touchsmartprinters.com",
        "touchsmartprinters.com",
        "www.wwwhpshopping.com",
        "touchsmartprinter.com",
        "www.hp.ca"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f310f300d060355040a1306485020496e63313630340603550403132d6870636f6d2d70726f2d646f6d61696e2d636c6f756466726f6e742d31332e6870636c6f75642e68702e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260716000000",
      "not_after": "20270130235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 302,
    "ptr": [
      "server-13-227-47-69.mci50.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 302,
    "root_location": "https://www.hp.com/",
    "http_status": 301,
    "p404_status": 302,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 302,
    "hsts": "max-age=31536000",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 302
  },
  "x16": {
    "root_status": 302,
    "cdn": [
      "CloudFront",
      "Fastly"
    ]
  },
  "x17": {
    "ocsp_http": "http://ocsp.digicert.com",
    "via": "1.1 91497c7d9eb98069bdcff6f49956c240.cloudfront.net (CloudFront)"
  },
  "elapsed_s": 11.4,
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
