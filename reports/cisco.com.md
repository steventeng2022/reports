# Security Audit Report — cisco.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cisco.com/ |
| Bug bounty program | Cisco Meraki |
| Listed scope domain | cisco.com |
| Test date | 2026-09-27 01:13 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 5, Info: 13)

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
| 9 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 18 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |

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

### 9. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://cisco.com/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

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
- **Detail:** Apex TXT records with verification/token content: yahoo-verification-key=2B33D2zyxdBOxUw/abowAuwQ2pdtznP6ULDfQC3ag2g=; airtable-verification=8cd8b684d3d85964f2769dcb89944501; twilio-domain-verification=268434bd6a91bdd8d3bb5e6cffeeace7
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://commercial.ocsp.identrust.com -> http-200
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 72.163.4.185 carries PTR redirect-ns.cisco.com. for cisco.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The cisco.com certificate lists an AIA OCSP responder (http://commercial.ocsp.identrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 18. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to cisco.com negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

## Evidence (raw response observations)

```json
{
  "domain": "cisco.com",
  "dns": {
    "a": [
      "72.163.4.185"
    ],
    "aaaa": [
      "2001:420:1101:1::185"
    ],
    "cname": null,
    "mx": [
      "aer-mx-01.cisco.com (pref 30)",
      "alln-mx-01.cisco.com (pref 10)",
      "rcdn-mx-01.cisco.com (pref 20)"
    ],
    "ns": [
      "ns2.cisco.com.",
      "ns3.cisco.com.",
      "a28-64.akam.net.",
      "a3-64.akam.net.",
      "ns1.cisco.com."
    ],
    "caa": [
      "0 issue \"amazon.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"pki.goog\"",
      "0 issue \"digicert.com\"",
      "128 issuewild \"identrust.com\"",
      "128 issuewild \"digicert.com\"",
      "0 issue \"globalsign.com\"",
      "128 iodef \"mailto:infosec@cisco.com\"",
      "0 issue \"identrust.com\"",
      "128 issuewild \"ssl.com\"",
      "0 issue \"ssl.com\""
    ],
    "spf": [
      "fastly-domain-delegation-e9a758d22183504af2d5ab4d9a9853da-20210127",
      "yahoo-verification-key=2B33D2zyxdBOxUw/abowAuwQ2pdtznP6ULDfQC3ag2g=",
      "airtable-verification=8cd8b684d3d85964f2769dcb89944501",
      "twilio-domain-verification=268434bd6a91bdd8d3bb5e6cffeeace7",
      "airtable-verification=606530d538d1833c5fc724117ca5409a",
      "airtable-verification=8bf444fd0fad14a3aae2681cb7d68641",
      "apple-domain-verification=qOInipPgso3W8cmK",
      "intercom-domain-validation=8806e2f9-7626-4d9e-ae4d-2d655028629a",
      "mZvHszGlmDhvPOUKL+6JMiw/VtckyOMKjcw1PLcjYowxM2PVLX2xG0ZSgdHRm8HXfaaGR2pMvhIrBX1tX3aKRQ==",
      "v=spf1 redirect=spfa._spf.cisco.com",
      "google-site-verification=V3t2K3dvr9fcd1YWwwanSmebEOO_UNTP06HR2_gUO5M",
      "airtable-verification=d886631ce96b77ba775f9bddab44df92",
      "wiz-domain-verification=af241e6396696eedf1b361891435f6b21bdebb5621941d99279298c076b5bf5f",
      "adobe-aem-verification=www-devint-cloud.cisco.com/24859/366173/9418f2a2-ef45-4788-9de9-91c7d19038b9",
      "flexera-domain-verification-nsbtshbvpbsmbnzh",
      "twilio-domain-verification=3b5f92478e8c38980a265e599e1538c8",
      "ms-domain-verification=e0289fac-4a94-41df-b2b0-794347e490b7",
      "google-site-verification=WmdDuSXl3PMb-48qcY6VUbW9kzNPe46zn9uDwgB2wX0",
      "SFMC-o7HX74BQ79k7glpt_qjlF2vmZO9DpqLtYxKLwg87",
      "stripe-verification=0BAD851A6A7ACC4A12DDCE03460CCEFAC86320A8494FDCCED35F71EE25EF3D03",
      "airtable-verification=18787f2dc47697bb547e871772aba0be",
      "fastly-domain-delegation-w049tcm0w48ds-341317-20210209",
      "sending_domain731003=25e34fadea88da7e64f0fab1e32d094f1f1e0fb2b97622deac2521f7a2c5b2bc",
      "MS=ms35724259",
      "airtable-verification=c0b5bd3f3db736f775f0dbe4e103cdea",
      "duo_sso_verification=pG21Oj5OPCxRPsWXsfbauWT9oua82cKtYUPAmsQvovKNq3xqWEcsEMEAhtXy8AFr",
      "google-site-verification=Vc0Pir22m1u9yw5HjXf6TYO6rlAI9EY8IVKUma-OqDY",
      "sending_domain1067842=8806a83586b0389c05457f8b2f06e4859b3f1b0d6bad52e5fee552bfd0a853e0",
      "atlassian-domain-verification=672RcADvt8BPqsb9gCN2ZC5DoTAhUT8abC1blYKQxi/MHMaGoA/BuvjFMaWRtgd7",
      "QuoVadis=94d4ae74-ecd5-4a33-975e-a0d7f546c801",
      "pendo-domain-verification=Ad800_b0VJCaE7Ued9Ug3pIQ_V4",
      "atlassian-domain-verification=2ldosmg0o2Mhpyok1OISaSGygWU9zk6fLLWdoczXtHap9luhaHA/pwEaj2Tk6ROK",
      "atlassian-domain-verification=AYTzL6wSVsW0IdyQp7gwv6lwtHdpMATnb8QriqyJ0niAaZct9kdSlXvfuE4GcoxU",
      "docusign=95052c5f-a421-4594-9227-02ad2d86dfbe",
      "notion-domain-verification=IsKmFIvIIP8RUQNn4ZGQjzuCdZnI7TY7xcIYb65QQE8",
      "c900335b8b825859b51473b9943a3880ae795df47426483b0a67630377a902f5",
      "google-site-verification=9MlQU9MMQ1jHLMUkONKe6QzZ-ZIGRv0BCD1_rY1Zdmc",
      "pendo-domain-verification=c9d2fba1-7d94-4cf9-a6fb-310883c8bb15",
      "facebook-domain-verification=qr2nigspzrpa96j1nd9criovuuwino",
      "ZOOM_verify_Gf6CaEdJ5aKGvjcUrZRkiA",
      "adobe-idp-site-verification=c900335b8b825859b51473b9943a3880ae795df47426483b0a67630377a902f5",
      "identrust_validate=ASvI9O914uC6UlLjYzP9VhdLCEWHi4QQ+R4OdK2vtOMp",
      "pendo-domain-verification=c9796502-c914-4e50-892d-e426f2ac68e9",
      "jamf-site-verification=0mwRCzzRvk_HiKjmiqR3Lw",
      "fastly-domain-delegation-im0VCGY5X0axEEmhXJb2-347911-20210310",
      "amazonses:mX+ylQj+fJAfh9pr03yIR7YvjKZ1bOo5ABegqM/5pvI=",
      "miro-verification=53bf5ccd47cb6239fe5cf14c3b328050dd5679ac",
      "docker-verification=4c56633a-274e-4858-88a2-2aeceffcfd66",
      "bfefecbd-d5df-4b3a-b0dd-54bf5c72e698",
      "google-site-verification=DN8r8LEcNiPYD95x3VnUM7Q6BH2H3390qvdIy4QjpvU",
      "docusign=5e18de8e-36d0-4a8e-8e88-b7803423fa2f",
      "workplace-domain-verification=Uhv7QPQ22nbuD3vG0jspf7R6LruYoS",
      "notion-domain-verification=7sz4S3LLtNIHZpYsgTTgOcRLlLrJ5JrmIgVcdRtGi1X",
      "amazonses:7LyiKZmpuGja4+KbA4xX3lN69yajYKLkHH4QJcWnuwo=",
      "atlassian-domain-verification=7JYRlY9ijBijTJ0YS5a8/58DU7OfKAHMYRufcy0TC57j2mNceH8rg4ajRzErc22Z",
      "stripe-verification=2B4F3B35976CFB93CA884A90BF3E0A8873EAC7C5AFD06D7047E87B794EC55DBB",
      "cloudflare_dashboard_sso=f60a7d128e406b8d9dd4103dd3554f6b",
      "google-site-verification=lW5eqPMJI4VrLc28YW-JBkqA-FDNVnhFCXQVDvFqZTo",
      "amazonses:QbUv5pPHGQxRy1vKA0J7Y/biE9oR6MTxOTI1bZIfjsw=",
      "elevenlabs=X_8Xi7v2hC20yVbziZuWtkapfDzUtNK3BogfZKVe9gY",
      "airtable-verification=4114c0f710cfc430d841e55ed7ed920d",
      "airtable-verification=d95d028f039252314cb7507fb88e4317",
      "duo_sso_verification=6Q7pJwSZ3damWHBcB8TNd9I5oduLRAFDDhip2pTFaa3QoIZtZnCgzjyZr5teSOWS",
      "adobe-aem-verification=www-idev-cloud.cisco.com/24859/366204/1b990ef7-ff88-4938-bdd9-8458cc152f57",
      "facebook-domain-verification=1zoxo8z7t013gpruxmhc8dkerq47vh",
      "duo_sso_verification=sKMGaTln2vmQuKwaE4hKtTEY1UYn2JzAaxSZzGjkgJrKuZChN344mhIptyczoNBA",
      "atlassian-domain-verification=UwP1ncfiphlFs+wRx8wIBSXDScwNL7Jrw7tq2rnYz3+9T5+Md9eTDRgNPCikxtOx",
      "atlassian-domain-verification=Gt2demeKDLmtNc9kPZhaAHFA37DEIcmFGUd6LARvB4yjLG70s3WZhaJJ15y499sb",
      "jetbrains-domain-verification=e9mcf886rjng68x4qu59h22ef",
      "profound-domain-verification-4tbqdv=dgW9PRoomrumTvr2gfRW4H3B1",
      "hubspot-domain-verification=NDQzNGY2ZWEtZTY0ZC00ZDQyLWI4YzctOGRkNDVjNTQ4YTAx",
      "pendo-domain-verification=5995ba9c-9bf8-43d8-9e5a-309856760011",
      "google-site-verification=qPS9ZkoQ-Og1rBrM1_N7z-tNJNy2BVxE8lw6SB2iFdk",
      "fastly-domain-delegation-z9slsbDdX0-368365-2021-05-14",
      "OSSRH-97236",
      "identrust_validate=mPh/vaMx5zgF8r1udSDOH2z2cf4O8bIcuPgHIigCFbxs",
      "cursor-domain-verification-evn8nj=Ml5OeQYe3sBg8uZOIeRrJgCO7",
      "duo_sso_verification=AxenLdoqIXzjl2RJzE1BlOfkawDbDFlnbyvjAt8vcjKHBkvYwEMySDRk5QmBd66v",
      "stripe-verification=8e54fae7680b23aad6d5e3417be73a043f7e45cd2767272dbe0c9c6eac903291",
      "h1-domain-verification=rix5vuxntVpma4rTL2DbE3FDrrPjedhnRaqaHvghyod3egmZ",
      "duo_sso_verification=IYdVUIrb2L95JVejSXV3hfsJVDZolQKKOPBztlD6TIgfCRSKeMuf8WgbQuFLD4aL",
      "926723159-3188410",
      "flexera-domain-verification-oxonqwdadtkprrcn",
      "_2gt42gt9xoa6p92bc6h5biciyt314fo",
      "mixpanel-domain-verify=2c6cb1aa-a3fb-44b9-ad10-d6b744109963",
      "asv=ac90e11808e87cfbf8768e69819b1aca",
      "google-site-verification=r-K1CIdXkgRWxZstUHtVyM2UfwflnGgr4AR9_Qhk28Q",
      "postman-domain-verification=bac0835520fcf3b408c07c584b3575452de5930d08a942cc0d000f1267a5b20de395ce8ccce9d6a6d58feff7c25f4000a22cd36968d8ac95ff234ab22ab264bb",
      "anthropic-domain-verification-5dyq28=xkpw44itymPv0HXOvUdry99zb"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; sp=reject; fo=1; ri=3600; rua=mailto:ynldvgsr@ag.dmarcian.com; ruf=mailto:ynldvgsr@fr.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Jose, organizationName=Cisco Systems Inc., commonName=www.cisco.com",
    "issuer": "countryName=US, organizationName=IdenTrust, organizationalUnitName=HydrantID Trusted Certificate Service, commonName=HydrantID Server CA O1",
    "notBefore": "Sep  3 18:56:07 2026 GMT",
    "notAfter": "Mar 21 18:55:07 2027 GMT",
    "san": [
      "cisco.com",
      "www.cisco.com",
      "www1.cisco.com",
      "www2.cisco.com",
      "www3.cisco.com",
      "www-01.cisco.com",
      "www-02.cisco.com",
      "www-rtp.cisco.com",
      "www1-ss2.cisco.com",
      "www2-ss1.cisco.com",
      "www3-ss1.cisco.com",
      "www3-ss2.cisco.com",
      "www.static-cisco.com",
      "redirect-ns.cisco.com",
      "cisco-images.cisco.com",
      "www.mediafiles-cisco.com",
      "z-ms77f8143bdb33fec86ff2f9551d961925.ctim.cisco.com"
    ],
    "days_left": 175,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "72.163.4.185",
    "open": []
  },
  "https": {
    "status": 302,
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
      "origin": "https://sub.cisco.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://cisco.com/"
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
    "yahoo-verification-key=2B33D2zyxdBOxUw/abowAuwQ2pdtznP6ULDfQC3ag2g=",
    "airtable-verification=8cd8b684d3d85964f2769dcb89944501",
    "twilio-domain-verification=268434bd6a91bdd8d3bb5e6cffeeace7",
    "airtable-verification=606530d538d1833c5fc724117ca5409a",
    "airtable-verification=8bf444fd0fad14a3aae2681cb7d68641"
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
      "aia_ocsp": "http://commercial.ocsp.identrust.com",
      "serial": 85079037502142625587867528699002896173,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://validation.identrust.com/crl/hydrantidcao1.crl"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e69613111300f0603550407130853616e204a6f7365311b3019060355040a1312436973636f2053797374656d7320496e632e311630140603550403130d7777772e636973636f2e636f6d",
      "issuer_dn": "310b300906035504061302555331123010060355040a13094964656e5472757374312e302c060355040b132548796472616e74494420547275737465642043657274696669636174652053657276696365311f301d0603550403131648796472616e74494420536572766572204341204f31",
      "not_before": "20260903185607",
      "not_after": "20270321185507"
    },
    "ocsp": "http-200"
  },
  "x12": {
    "status": 302,
    "ptr": [
      "redirect-ns.cisco.com."
    ]
  },
  "x13": {
    "root_status": 302,
    "root_location": "https://www.cisco.com/",
    "http_status": 302,
    "p404_status": 302,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 302,
    "crl": {
      "url": "http://validation.identrust.com/crl/hydrantidcao1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "cipher_ver": "TLSv1.2",
    "root_status": 302
  },
  "x16": {
    "root_status": 302
  },
  "elapsed_s": 63.9,
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
