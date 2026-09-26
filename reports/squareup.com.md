# Security Audit Report — squareup.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://squareup.com/ |
| Bug bounty program | Square |
| Listed scope domain | squareup.com |
| Test date | 2026-09-26 23:38 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 3, Info: 21)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 20 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 21 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 22 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 23 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 24 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.136.66:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.136.66:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: stripe-verification=5a8a00371398aa2466b713faf14e6edc9140160c32f51d02067af5dcd859; stripe-verification=cfd5f1b3267861ed07fba1b121f0161da96c9fb30c97f590fc88db51506b; pinterest-site-verification=49699bc2c694be95ffea5692960d72b4
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of squareup.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but squareup.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 39 disallow path(s), e.g. */detect_country.json, */tracking.json, */test/, */appointments/mapbox/, */appointments/book/profile/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://squareup.com/ carries Cache-Control: max-age=0, public, must-revalidate; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 20. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on squareup.com indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 21. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkx9elzy6akfii.html -> 404; error page/headers match: Cloudflare.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 22. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on squareup.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 23. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for squareup.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 24. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on squareup.com lists 16 <loc> URL(s) across 17 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

## Evidence (raw response observations)

```json
{
  "domain": "squareup.com",
  "dns": {
    "a": [
      "162.159.136.66",
      "162.159.137.66"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx3.googlemail.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx5.googlemail.com (pref 30)",
      "aspmx4.googlemail.com (pref 30)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-810.awsdns-37.net.",
      "ns-1248.awsdns-28.org.",
      "ns-1816.awsdns-35.co.uk.",
      "ns-311.awsdns-38.com."
    ],
    "caa": [],
    "spf": [
      "ca3-37fc58abdd5a4cf8ab5e8893db8298be",
      "stripe-verification=5a8a00371398aa2466b713faf14e6edc9140160c32f51d02067af5dcd8591cc8",
      "stripe-verification=cfd5f1b3267861ed07fba1b121f0161da96c9fb30c97f590fc88db51506b4710",
      "ca3-52a6dd26ecd1423ca816dac4d4b00678",
      "pinterest-site-verification=49699bc2c694be95ffea5692960d72b4",
      "NRZYY",
      "traction-guest=2bfeba2a-05af-4152-a3ab-93d855c8746f",
      "_github-challenge-squareup.squareup.com.=7725774663",
      "google-site-verification=lIzmfEdVTz2PAEu4n8NckVPZhd-mQiGTlc0xBXlOhtU",
      "_ek1nrewwbsrikaiet5cox7909jno0th",
      "v=spf1 include:squareup.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:stspg-customer.com ~all",
      "ca3-c491f3300b6641e1b8a3104b693d7bb3",
      "pinterest-site-verification=0fef3763fa30d8b29fca02b8d1e77626",
      "ca3-8bbc566c4b4c4974950a83527517492d",
      "ca3-e9926e04f8c148e89e7c600213cb986a",
      "parsec-domain-verification=td_2c0ZaSdVBfxDHQsb5HjmvQCHaKF",
      "facebook-domain-verification=ddco927gzciui72ra27s2aq1301vjo",
      "_y1htjeszjqrpqpxssty0ae0ks9losgo",
      "logmein-verification-code=d29bfe7e-a479-4ca9-862a-c87f1072f273",
      "smartsheet-site-validation=W_x3SnUQHna2UrcNnqg-4GMu73nsWryz",
      "miro-verification=eb2231722e9ee6e925e69e31c221403361bbc1cb",
      "ca3-a19f55866123448fb9e26ff3ed0d6d86",
      "notion_verify_3U}dr=+.N}vm0w.DoqiC%JJ}N0W5^}hnd1Wus9zb^EVJDw9pD%jG)hQ}V__qkd3U)4s!Xp",
      "ca3-61da443be93c4975accb29e3bbf89560",
      "amp-by-sourcegraph-domain-verification-w953qg=xBRagiAevq79uusplKZZPSBsg",
      "1e2c0716300b68209485e2fa5284112046f593dcafc636f07969741ef148c441",
      "facebook-domain-verification=cx3tov4g02lrdyzawmw6zfl8zgrc5c",
      "onetrust-domain-verification=c01f4d184d3c4f2ba9503a4583e88101",
      "drift-domain-verification=71b345a7ff662bf9535a86f2ddbb50016872b37a56c6988edd6c39542a3ccd68",
      "ca3-a3666da4d1ec4264a8d59cb8616cf0ed",
      "cursor-domain-verification-zvsqws=WAenirNPzeew2GcY4MKkAk41T",
      "docusign=35ce9b6e-d74a-48ad-b437-690ad0602f81",
      "elevenlabs=SBg1u4pIdlsVtIaiXt8QeVV3yNEzeNtNs51br5upR4g",
      "_github-challenge-squareup.squareup.com=7725774663",
      "stripe-verification=65D5F85D03979AEEF3452A27D1EFACD75E9D04DCC44E1BC99F4EBBCFCB7F8F26",
      "ca3-4725c4c959644520b1df50805f72dca7",
      "atlassian-domain-verification=9iYUpJGNkg1t97CI3rPIi2JSZhPPPq2vqa29bn1XafOtu0579nFxEzSX3VzIvcRm",
      "apple-domain-verification=sRlD9NsdK27SFZHX",
      "anthropic-domain-verification-7xmqab=NeSCp0Pj0sOrdc5jJgJiOsHFb",
      "docusign=60c2f7db-b230-4b3d-91be-06a59569d253",
      "asv=2196a8f94eda64bc9d0abd83d4b93284",
      "ca3-bd8eae9a6ea245b68811b976990fc57d",
      "atlassian-sending-domain-verification=e540d827-02ac-4946-acee-a77c1df352f6",
      "docker-verification=4ed46600-9205-400a-b12d-d0135704e9e9",
      "gitkraken-domain-verification=8e6bcedb6a5ded444186409140245b606ca0417109d394ee4e5b2b7df5e56ee0",
      "bugcrowd-verification=2aa613d4e374f9460060422314f1098d",
      "loom-site-verification=0036b963640944f580e4c1fec45c8d9d",
      "google-site-verification=mlc7S_Dm5aPcPQjEe_Pj3GuiF9_svNtafsWw_kPeN48",
      "google-site-verification=OuiYXiYuWdfPSus7uBL6EhJawkg5BOERlvclE-QXVcs",
      "lucidlink-verification=9W8003J10X2KM6X9SS663MSG08",
      "wiz-domain-verification=e401377ed0542bf72e67d32b62781795a75cfc1a84c18520e6263bfdf415cd0e",
      "decagon-domain-verification-r97he8=KlORBvkU6R2syjbUBJ4eWNRp2",
      "google-site-verification=xoi3YhHkHmKwoyDO259v-DxMgY38xT08RNKMLTtTJ3A",
      "1password-site-verification=DREX2J7TXBEY5FGM2RYXBK366U",
      "figma-domain-verification=be3dd0262e644143f217f04e38b0e10fdf5a22fd0f1552912f229dbc5cfc04ef-1785184551",
      "onetrust-domain-verification=0c79435fab8d45ac85eb4ac5041ab282",
      "postman-domain-verification=a3440d0a55ffe5831bf45b9bb5136601ebf884dd1cb5a755daaa73104b1f682d6d88d0a4741b6eef6a33b6d69f1856366a06433b7902f85bafb358ea854552f9",
      "status-page-domain-verification=75bhj6n7cwrd",
      "zapier-domain-verification-challenge=9b5ca019-06d3-40bb-a52b-915e42e1d884",
      "wrike-verification=MzIwNzgwMDo2MGE1NjUwYThkMmExMjkzZDg3MGVmMDE3MzkzMDJlOTE4YTY5YmZlMjNlZGE5MGY5MWMzODFhNTFmNDU5MTNi",
      "ca3-60ed3ea4c1e141c79e4715175c4342f3",
      "google-site-verification=DsJnK_h3aiHyf-DRKaVdc_iNooeRxSGu8PqkY2KTd74",
      "google-site-verification=Pqbi42Git5I6oJ6ShnRd4aUd2umxUHL5JAKHf_kSQwQ",
      "MS=ms66034408",
      "ca3-6a7c53b6aded4260a698de411a9640b8",
      "reachdesk-verification=IjVgh43q7kQHr9cSU6FYVjktOt6FNW6I1VKqC7cLSPXDW0hqMpa5pPjEJ39dnG99",
      "docusign=83d5eb19-7a3d-4191-99f9-1f2c4e94fdfa",
      "ca3-2cc3579a5da949a0bd2bc349e2b82c52",
      "google-site-verification=UVRQgeyjSjLUSa6l8xBu1fNQBxxKOL85Pg4457B-oms"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email,mailto:postmasters@squareup.com,mailto:square-dmarc@datafeeds.phishlabs.com; ruf=mailto:dmarc-ruf@squareup.com,mailto:square-dmarc@datafeeds.phishlabs.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=squareup.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug  2 18:56:43 2026 GMT",
    "notAfter": "Oct 31 19:56:17 2026 GMT",
    "san": [
      "squareup.com",
      "jobs.squareup.com",
      "sentry.squareup.com",
      "origin-careers.squareup.com",
      "blog.squareup.com",
      "sc-connect.squareup.com",
      "corner-move.squareup.com",
      "brand.squareup.com",
      "www.squareup.com",
      "ocr-connect.squareup.com",
      "fulfillment.squareup.com",
      "design.squareup.com",
      "privacy.squareup.com",
      "localizer.squareup.com"
    ],
    "days_left": 34,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "162.159.136.66",
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
      "samesite": "strict"
    },
    {
      "domain": "squareup.com",
      "samesite": "strict"
    },
    {
      "domain": "squareup.com",
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
      "origin": "https://sub.squareup.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://squareup.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "stripe-verification=5a8a00371398aa2466b713faf14e6edc9140160c32f51d02067af5dcd859",
    "stripe-verification=cfd5f1b3267861ed07fba1b121f0161da96c9fb30c97f590fc88db51506b",
    "pinterest-site-verification=49699bc2c694be95ffea5692960d72b4",
    "google-site-verification=lIzmfEdVTz2PAEu4n8NckVPZhd-mQiGTlc0xBXlOhtU",
    "pinterest-site-verification=0fef3763fa30d8b29fca02b8d1e77626"
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
      "aia_ocsp": null,
      "serial": 60529212256975099404046944671528761180,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/we1/0rbAgG3gMgU.crl"
      ],
      "subject_dn": "311530130603550403130c73717561726575702e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531",
      "not_before": "20260802185643",
      "not_after": "20261031195617"
    }
  },
  "http2": {
    "robots_disallow": [
      "*/detect_country.json",
      "*/tracking.json",
      "*/test/",
      "*/appointments/mapbox/",
      "*/appointments/book/profile/",
      "*/capital/consumer/invoice/merchants/",
      "*/form/",
      "*/gift/",
      "*/i/",
      "*/pay-invoice/",
      "*/password/",
      "*/r/",
      "*/signup?signup_token=*",
      "*/subscriptions/",
      "*/email/subscriptions/"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "/us/en",
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=631152000; includeSubDomains; preload",
    "sitemap": {
      "urls": 16,
      "indexes": 17
    },
    "crl": {
      "url": "http://c.pki.goog/we1/0rbAgG3gMgU.crl",
      "status": 200
    }
  },
  "elapsed_s": 10.0,
  "rechecked": "2026-09-26 23:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- Findings are reported against the public program scope; submission through the program tracker is pending.
