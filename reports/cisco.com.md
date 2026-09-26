# Security Audit Report — cisco.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cisco.com/ |
| Bug bounty program | Cisco Meraki |
| Listed scope domain | cisco.com |
| Test date | 2026-09-25 09:02 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 4, Info: 6)

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
      "ns3.cisco.com.",
      "ns1.cisco.com.",
      "ns2.cisco.com.",
      "a3-64.akam.net.",
      "a28-64.akam.net."
    ],
    "spf": [
      "flexera-domain-verification-oxonqwdadtkprrcn",
      "pendo-domain-verification=c9796502-c914-4e50-892d-e426f2ac68e9",
      "airtable-verification=d886631ce96b77ba775f9bddab44df92",
      "sending_domain731003=25e34fadea88da7e64f0fab1e32d094f1f1e0fb2b97622deac2521f7a2c5b2bc",
      "jamf-site-verification=0mwRCzzRvk_HiKjmiqR3Lw",
      "docusign=5e18de8e-36d0-4a8e-8e88-b7803423fa2f",
      "fastly-domain-delegation-w049tcm0w48ds-341317-20210209",
      "sending_domain1067842=8806a83586b0389c05457f8b2f06e4859b3f1b0d6bad52e5fee552bfd0a853e0",
      "airtable-verification=4114c0f710cfc430d841e55ed7ed920d",
      "pendo-domain-verification=c9d2fba1-7d94-4cf9-a6fb-310883c8bb15",
      "926723159-3188410",
      "bfefecbd-d5df-4b3a-b0dd-54bf5c72e698",
      "pendo-domain-verification=Ad800_b0VJCaE7Ued9Ug3pIQ_V4",
      "duo_sso_verification=AxenLdoqIXzjl2RJzE1BlOfkawDbDFlnbyvjAt8vcjKHBkvYwEMySDRk5QmBd66v",
      "postman-domain-verification=bac0835520fcf3b408c07c584b3575452de5930d08a942cc0d000f1267a5b20de395ce8ccce9d6a6d58feff7c25f4000a22cd36968d8ac95ff234ab22ab264bb",
      "cursor-domain-verification-evn8nj=Ml5OeQYe3sBg8uZOIeRrJgCO7",
      "adobe-aem-verification=www-idev-cloud.cisco.com/24859/366204/1b990ef7-ff88-4938-bdd9-8458cc152f57",
      "google-site-verification=lW5eqPMJI4VrLc28YW-JBkqA-FDNVnhFCXQVDvFqZTo",
      "stripe-verification=2B4F3B35976CFB93CA884A90BF3E0A8873EAC7C5AFD06D7047E87B794EC55DBB",
      "ZOOM_verify_Gf6CaEdJ5aKGvjcUrZRkiA",
      "duo_sso_verification=IYdVUIrb2L95JVejSXV3hfsJVDZolQKKOPBztlD6TIgfCRSKeMuf8WgbQuFLD4aL",
      "amazonses:QbUv5pPHGQxRy1vKA0J7Y/biE9oR6MTxOTI1bZIfjsw=",
      "airtable-verification=606530d538d1833c5fc724117ca5409a",
      "google-site-verification=9MlQU9MMQ1jHLMUkONKe6QzZ-ZIGRv0BCD1_rY1Zdmc",
      "airtable-verification=8cd8b684d3d85964f2769dcb89944501",
      "workplace-domain-verification=Uhv7QPQ22nbuD3vG0jspf7R6LruYoS",
      "google-site-verification=qPS9ZkoQ-Og1rBrM1_N7z-tNJNy2BVxE8lw6SB2iFdk",
      "c900335b8b825859b51473b9943a3880ae795df47426483b0a67630377a902f5",
      "flexera-domain-verification-nsbtshbvpbsmbnzh",
      "atlassian-domain-verification=UwP1ncfiphlFs+wRx8wIBSXDScwNL7Jrw7tq2rnYz3+9T5+Md9eTDRgNPCikxtOx",
      "fastly-domain-delegation-z9slsbDdX0-368365-2021-05-14",
      "asv=ac90e11808e87cfbf8768e69819b1aca",
      "MS=ms35724259",
      "duo_sso_verification=6Q7pJwSZ3damWHBcB8TNd9I5oduLRAFDDhip2pTFaa3QoIZtZnCgzjyZr5teSOWS",
      "mixpanel-domain-verify=2c6cb1aa-a3fb-44b9-ad10-d6b744109963",
      "google-site-verification=V3t2K3dvr9fcd1YWwwanSmebEOO_UNTP06HR2_gUO5M",
      "notion-domain-verification=IsKmFIvIIP8RUQNn4ZGQjzuCdZnI7TY7xcIYb65QQE8",
      "adobe-idp-site-verification=c900335b8b825859b51473b9943a3880ae795df47426483b0a67630377a902f5",
      "OSSRH-97236",
      "amazonses:mX+ylQj+fJAfh9pr03yIR7YvjKZ1bOo5ABegqM/5pvI=",
      "elevenlabs=X_8Xi7v2hC20yVbziZuWtkapfDzUtNK3BogfZKVe9gY",
      "twilio-domain-verification=3b5f92478e8c38980a265e599e1538c8",
      "wiz-domain-verification=af241e6396696eedf1b361891435f6b21bdebb5621941d99279298c076b5bf5f",
      "yahoo-verification-key=2B33D2zyxdBOxUw/abowAuwQ2pdtznP6ULDfQC3ag2g=",
      "cloudflare_dashboard_sso=f60a7d128e406b8d9dd4103dd3554f6b",
      "google-site-verification=DN8r8LEcNiPYD95x3VnUM7Q6BH2H3390qvdIy4QjpvU",
      "atlassian-domain-verification=Gt2demeKDLmtNc9kPZhaAHFA37DEIcmFGUd6LARvB4yjLG70s3WZhaJJ15y499sb",
      "airtable-verification=18787f2dc47697bb547e871772aba0be",
      "v=spf1 redirect=spfa._spf.cisco.com",
      "stripe-verification=8e54fae7680b23aad6d5e3417be73a043f7e45cd2767272dbe0c9c6eac903291",
      "atlassian-domain-verification=7JYRlY9ijBijTJ0YS5a8/58DU7OfKAHMYRufcy0TC57j2mNceH8rg4ajRzErc22Z",
      "apple-domain-verification=qOInipPgso3W8cmK",
      "SFMC-o7HX74BQ79k7glpt_qjlF2vmZO9DpqLtYxKLwg87",
      "miro-verification=53bf5ccd47cb6239fe5cf14c3b328050dd5679ac",
      "adobe-aem-verification=www-devint-cloud.cisco.com/24859/366173/9418f2a2-ef45-4788-9de9-91c7d19038b9",
      "google-site-verification=r-K1CIdXkgRWxZstUHtVyM2UfwflnGgr4AR9_Qhk28Q",
      "pendo-domain-verification=5995ba9c-9bf8-43d8-9e5a-309856760011",
      "atlassian-domain-verification=AYTzL6wSVsW0IdyQp7gwv6lwtHdpMATnb8QriqyJ0niAaZct9kdSlXvfuE4GcoxU",
      "stripe-verification=0BAD851A6A7ACC4A12DDCE03460CCEFAC86320A8494FDCCED35F71EE25EF3D03",
      "atlassian-domain-verification=672RcADvt8BPqsb9gCN2ZC5DoTAhUT8abC1blYKQxi/MHMaGoA/BuvjFMaWRtgd7",
      "facebook-domain-verification=1zoxo8z7t013gpruxmhc8dkerq47vh",
      "intercom-domain-validation=8806e2f9-7626-4d9e-ae4d-2d655028629a",
      "mZvHszGlmDhvPOUKL+6JMiw/VtckyOMKjcw1PLcjYowxM2PVLX2xG0ZSgdHRm8HXfaaGR2pMvhIrBX1tX3aKRQ==",
      "anthropic-domain-verification-5dyq28=xkpw44itymPv0HXOvUdry99zb",
      "_2gt42gt9xoa6p92bc6h5biciyt314fo",
      "google-site-verification=WmdDuSXl3PMb-48qcY6VUbW9kzNPe46zn9uDwgB2wX0",
      "twilio-domain-verification=268434bd6a91bdd8d3bb5e6cffeeace7",
      "facebook-domain-verification=qr2nigspzrpa96j1nd9criovuuwino",
      "jetbrains-domain-verification=e9mcf886rjng68x4qu59h22ef",
      "hubspot-domain-verification=NDQzNGY2ZWEtZTY0ZC00ZDQyLWI4YzctOGRkNDVjNTQ4YTAx",
      "airtable-verification=d95d028f039252314cb7507fb88e4317",
      "amazonses:7LyiKZmpuGja4+KbA4xX3lN69yajYKLkHH4QJcWnuwo=",
      "ms-domain-verification=e0289fac-4a94-41df-b2b0-794347e490b7",
      "airtable-verification=c0b5bd3f3db736f775f0dbe4e103cdea",
      "duo_sso_verification=sKMGaTln2vmQuKwaE4hKtTEY1UYn2JzAaxSZzGjkgJrKuZChN344mhIptyczoNBA",
      "identrust_validate=ASvI9O914uC6UlLjYzP9VhdLCEWHi4QQ+R4OdK2vtOMp",
      "fastly-domain-delegation-im0VCGY5X0axEEmhXJb2-347911-20210310",
      "fastly-domain-delegation-e9a758d22183504af2d5ab4d9a9853da-20210127",
      "docker-verification=4c56633a-274e-4858-88a2-2aeceffcfd66",
      "h1-domain-verification=rix5vuxntVpma4rTL2DbE3FDrrPjedhnRaqaHvghyod3egmZ",
      "airtable-verification=8bf444fd0fad14a3aae2681cb7d68641",
      "duo_sso_verification=pG21Oj5OPCxRPsWXsfbauWT9oua82cKtYUPAmsQvovKNq3xqWEcsEMEAhtXy8AFr",
      "notion-domain-verification=7sz4S3LLtNIHZpYsgTTgOcRLlLrJ5JrmIgVcdRtGi1X",
      "identrust_validate=mPh/vaMx5zgF8r1udSDOH2z2cf4O8bIcuPgHIigCFbxs",
      "docusign=95052c5f-a421-4594-9227-02ad2d86dfbe",
      "google-site-verification=Vc0Pir22m1u9yw5HjXf6TYO6rlAI9EY8IVKUma-OqDY",
      "atlassian-domain-verification=2ldosmg0o2Mhpyok1OISaSGygWU9zk6fLLWdoczXtHap9luhaHA/pwEaj2Tk6ROK",
      "profound-domain-verification-4tbqdv=dgW9PRoomrumTvr2gfRW4H3B1",
      "QuoVadis=94d4ae74-ecd5-4a33-975e-a0d7f546c801"
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
    "days_left": 177,
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
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 137.1,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
