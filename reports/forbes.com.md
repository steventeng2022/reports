# Security Audit Report — forbes.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://forbes.com/ |
| Bug bounty program | Forbes |
| Listed scope domain | forbes.com |
| Test date | 2026-09-26 17:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 3, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | low | CORS1 | CORS: subdomain origin origin accepted with credentials | CWE-942 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443";ma=86400,h3-29=":443";ma=86400,h3-27=":443";ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [LOW] CORS: subdomain origin origin accepted with credentials (`CORS1`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.forbes.com -> Access-Control-Allow-Origin: https://sub.forbes.com, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 10. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=Xn4XFgtsz0Vg597dd8D8rO4jI6vC9pB7yseCSveG3h8; google-site-verification=2LeumZRvIXuK3YrTI2IsISp06lXZpHCY1ql9Hdnm7ok; teamviewer-sso-verification=27c248ca0d8b4160ae3d1de1a514f350
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of forbes.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1052 disallow path(s), e.g. /following/, /search/, /follow/, /ajax/, /author/following/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "forbes.com",
  "dns": {
    "a": [
      "151.101.66.49",
      "151.101.194.49",
      "151.101.2.49",
      "151.101.130.49"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "us-smtp-inbound-2.mimecast.com (pref 10)",
      "us-smtp-inbound-1.mimecast.com (pref 10)"
    ],
    "ns": [
      "ns-217.awsdns-27.com.",
      "ns-979.awsdns-58.net.",
      "ns-1028.awsdns-00.org.",
      "ns-1637.awsdns-12.co.uk."
    ],
    "spf": [
      "smartsheet-site-validation=cK_DmMDOyw92iKzuKOQwA0xEgc1QbECt",
      "sending_domain1025723=07a4a21499775df2794df065a6dc2e7c2c01a21593cea6162497f05bca993eaa",
      "SFMC-bcDxiJPY-jXu5QtysqxbFjCPLBjk3BSojw81lQrU",
      "google-site-verification=Xn4XFgtsz0Vg597dd8D8rO4jI6vC9pB7yseCSveG3h8",
      "google-site-verification=2LeumZRvIXuK3YrTI2IsISp06lXZpHCY1ql9Hdnm7ok",
      "teamviewer-sso-verification=27c248ca0d8b4160ae3d1de1a514f350",
      "pardot1032633=53abf112b6eecacc916172589fb4d4bd8c30db4bd1b5330035aa2b700d3ed6b0",
      "1password-site-verification=VJAHF3DA3ZEJ7J26NH4WJ4QDYI",
      "google-site-verification=Cv7OXjshytFn0TpR1rgKpHjEY_fROROE67OtoFceBqo",
      "AiAIjH5HOXMx5tZiyBtD0B/u8mG9qKWaux3SehpuJOv0F+5AvjwJTKsIeI7HR3DR0QDYmJthhZvN8ScuEO9LqA==",
      "google-site-verification=cXpgpgls018QgvO6u7ZwfMVCNWo_woBz1bvNa4UoBEQ",
      "google-site-verification=Y4n4S0k7HGrE1sAHYlupK4YAjw4d_oSAeoGy6mLe8Mw",
      "google-site-verification=4RdeC2A3Yjqca3_jGnjXGOYJFTVOzhMDw1SoOO7b6Dw",
      "pardot801473=19f8d9f3e51ca9f5e26b0d692435f822cdca35fb4777c78de68ae6c257d5b038",
      "teamviewer-sso-verification=d48556548a9646a3af6d65f6f2da0bff",
      "google-site-verification=xE03wJxteQXWM1cwqmiAVTgaQ3StFNRzuCXOobAACEs",
      "stripe-verification=0d973d45747a457f5e2624c6116631d31e007d32d42654cca280f9b38da539f3",
      "v=spf1 redirect=b45gkw7f._spf._d.mim.ec",
      "shopify-verification-code=ylk8pVI1nugZQA5xPbN6LkHm7sD6CK",
      "datadome-domain-verify=gH4f7bbJndRTMUSvjv8PAP8SOlVa8wKW",
      "mandrill_verify.3ujpkQolFHR740mhYiRgYw",
      "_globalsign-domain-verification=yMOGr8PalNMtvZPeSrDGFdvgJfngIvOKMbvhlujB3j",
      "google-site-verification=nPz5kafgk6DGWCT24sR_kxBZ6HdDWmVEPcT67LVTDi4",
      "pardot801473=bf9d7022b0bc982f001c58f637feb87b69c9c2b03e8a6b856130925bea8ac117",
      "anthropic-domain-verification-09rb60=Yuv8hcWdMxtF6VbmFFZFQNzTn",
      "google-site-verification=DN-rZTjK3vdARCxismMt2SJDfV2969vhf1paBECwEMM",
      "klaviyo-site-verification=UkVi3K",
      "docusign=d1893713-45af-4fd3-8a65-3ea6d0805b8d",
      "box-domain-verification=a168e4b0fb547cea9aad102fd5b98ad61fc358ddd6ab17b084a1defac10e562a",
      "adobe-idp-site-verification=a6de0a21210eae1c4187cfe64dfb37d7920d64e696bdfb0cad32d55ca6878c06",
      "google-site-verification=Q0R44HZFT_-piE4edEVS_jGwyMFoOX4OZ9TGe6zTdys",
      "tollbit-domain-verification=f8c8756d26a28b62f839818a4beacd34fb4032d5c5dad7f2bea69856cf265082",
      "_globalsign-domain-verification=OYfE_CcZQWFlEEOrR5yVCfCtmiQrm0bBdyUAJyg3qE",
      "monday-com-verification=ndOawG8XV4mwyFS7aJZKgKvfWc_nN6gc6_5rUrvAS7A",
      "MS=ms55849810",
      "pardot862611=cc07d11f1e6b06dc86f90b7be4df47547054f36ffae67809000382108c396476",
      "google-site-verification=yZQq_-7hQQZvLkdcyiFtwW6OR3Z622l79OSUvBRsqNc",
      "jamf-site-verification=yHj9RKO_tLsE0_uN0pJFnA",
      "klaviyo-site-verification=UeguZL",
      "detectify-verification=5f8e1d4a06c492a8ba7c03abd2c0ef89",
      "pardot796133=6fd42896c075674c6c76877e3b89bdf5968ef1481049531e12ea9bdb8f2ff83e",
      "pardot1025723=b54db22127fb6a86162b160a380d9c5c2c50bcb8cb300ab427037bbc1b85407c",
      "_globalsign-domain-verification=neaEg6fJBhW6Tg3gVqQJIn6pLyiBwIiDdxJ88CLzP6",
      "sending_domain1032633=35ec75414af614386e4c539f6b6f70dec43759367a0507621bf72396033c96df",
      "google-site-verification=lYYbu_dzlcI_soF2GSXrdoAGm2XDbIAjDZyu0vhKwxc",
      "activeprospect-domain-verification=qp+SZ6XBnvREh9uEL2xQLA==",
      "pardot796133=9f1e666d7433483f4b9dc2e20e381f5585877aded11d3d17f1f597438ebb9726",
      "activeprospect-domain-verification=ua2Bpiq7hQeM3lYKH8kgnQ==",
      "atlassian-domain-verification=+tjT1PDHq7a3IkqoEdD/cr2krJeRPoT5b6MzfYBKGS4UnVXhIHyuSJjSIxijiVSQ",
      "_globalsign-domain-verification=f-B_7ErtvSe_2e1SkhSsTab6DQA-AVd2vcvY3gqskQ",
      "_globalsign-domain-verification=uJqsSX1GhpaZSFMhWB8VnlSbH-6c3GbKG4zsuqlwcx",
      "00DA0000000H8gQ=1TBUs0000000B8L",
      "apple-domain-verification=daIrUUF2LjNKeFrq",
      "loom-site-verification=2203b12049644a5f96f8b3027d420d7f",
      "canva-site-verification=0wNoieRvIbw1yAsgkfgEFg",
      "mgverify=735062366c4a3c7a10b6c50bcba26706a11ad9fc277ff9b88f65478b3517f0a1",
      "openai-domain-verification=dv-w07b4qQxAzb1Klu9YesisWnX"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:dmarcreports@forbes.com,mailto:69955ab810e8779@rep.dmarcanalyzer.com; ruf=mailto:69955ab810e8779@for.dmarcanalyzer.com; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=forbes.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2025 Q4",
    "notBefore": "Nov 10 19:01:53 2025 GMT",
    "notAfter": "Dec 12 19:01:52 2026 GMT",
    "san": [
      "forbes.com"
    ],
    "days_left": 77,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "151.101.66.49",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": "true"
    },
    {
      "origin": "https://sub.forbes.com",
      "acao": "https://sub.forbes.com",
      "acac": "true"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://forbes.com/"
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
    "google-site-verification=Xn4XFgtsz0Vg597dd8D8rO4jI6vC9pB7yseCSveG3h8",
    "google-site-verification=2LeumZRvIXuK3YrTI2IsISp06lXZpHCY1ql9Hdnm7ok",
    "teamviewer-sso-verification=27c248ca0d8b4160ae3d1de1a514f350",
    "1password-site-verification=VJAHF3DA3ZEJ7J26NH4WJ4QDYI",
    "google-site-verification=Cv7OXjshytFn0TpR1rgKpHjEY_fROROE67OtoFceBqo"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/following/",
      "/search/",
      "/follow/",
      "/ajax/",
      "/author/following/",
      "/blog/following/",
      "/json/",
      "/header/channels/",
      "/find-more/",
      "/preview/",
      "*wp-admin*",
      "/typeahead/",
      "/pepe/",
      "/media-manager/",
      "/coupons/visit/*"
    ]
  },
  "elapsed_s": 18.4,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
