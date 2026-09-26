# Security Audit Report — xing.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://xing.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | xing.com |
| Test date | 2026-09-26 19:02 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 4, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 19 | info | CT1 | 370 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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
- **Detail:** Header reveals: CloudFront
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

### 13. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (yxyasu4kotk9u1.xing.com and p62zhg4wsfhmmn.xing.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=jC5_MqgVlYS7He0-uldAaB4z1uYxuZUKL_bTHaIYn-0; atlassian-domain-verification=jQie6vPSfhfQ4wsCwYZtuCQTWC7PhDbv9HmrAzbRc6skBWWB/T; facebook-domain-verification=xxd0q3s7lv62wywvvpver0e8j1j1vw
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of xing.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but xing.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 235 disallow path(s), e.g. /, /img/users, /app/search, /cgi-bin/search.fpl, /patterns
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 18.154.144.107 carries PTR server-18-154-144-107.lax50.r.cloudfront.net. for xing.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 19. [INFO] 370 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.preview.xing.com, admin.xing.com, api.ams1.xing.com, api.ams2.xing.com, api.preview.ams1.xing.com, api.preview.ams2.xing.com, api.preview.xing.com, api.xing.com, blog.xing.com, dev.preview.xing.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "xing.com",
  "dns": {
    "a": [
      "18.154.144.107",
      "18.154.144.64",
      "18.154.144.42",
      "18.154.144.78"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "xing-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns-1321.awsdns-37.org.",
      "ns-633.awsdns-15.net.",
      "ns-291.awsdns-36.com.",
      "ns-1690.awsdns-19.co.uk."
    ],
    "spf": [
      "v=spf1 mx include:_netblocks.mail.xing.com include:_spf.zimpel.de include:_spf.salesforce.com include:_spf.abiliware.de ?include:servers.mcsv.net include:spf.protection.outlook.com include:mail.zendesk.com ~all",
      "_oqnb58q3pbnwofdf7gr0jeab8ik8xs6",
      "google-site-verification=jC5_MqgVlYS7He0-uldAaB4z1uYxuZUKL_bTHaIYn-0",
      "atlassian-domain-verification=jQie6vPSfhfQ4wsCwYZtuCQTWC7PhDbv9HmrAzbRc6skBWWB/TfL8TpiAqozsb8N",
      "facebook-domain-verification=xxd0q3s7lv62wywvvpver0e8j1j1vw",
      "google-site-verification=1CoJURTg2aHLa8bvDoNt_dDrLNmVPE93-cjaxYitSo8",
      "ZOOM_verify_av-wjAz-T62Xdl1pMRBySA",
      "segment-site-verification=3fA98vkzGDmgoJbj3AG2CJvr8Z9mSQpx",
      "figma-domain-verification=021dc2f32684e858eaf9842b7206f9197bbdffa76c83ac711b16ba9702aeca5c-1782465718",
      "astro-domain-verification=clyhbm3ib0dq801kip93vxw0t",
      "google-site-verification=Flhe3fswMbbqS2VGEy2ODM-1P_PE_Z5l2u5zZZq5UR4",
      "MS=ms45637936",
      "Ml9vw8Cm/Ig/xpmhhDfS9TEjuzw=",
      "teamviewer-sso-verification=54188f7fff354a9b92f7652fd3937fb0",
      "google-site-verification=UqxFvQ_ikK9hga0Qm1unOA9HbMWTTlJ_TTVxRTu9z04",
      "zoom-domain-verification=5adddeb4-2a0b-4bf0-8eaf-82bc5e2c49d8",
      "docker-verification=7d460483-f122-4277-b449-0a3a3fe26190",
      "MS=ms63761438",
      "docusign=73ffe7e4-a802-458a-bad3-3afefc637792",
      "openai-domain-verification=dv-JfWX8IbG0n87GNHoDQvLlbeM",
      "google-site-verification=Qb3_TK55U83JNTsumhQ_7culHoFKMU2dcpvVvfl5h-k",
      "TTmNrvKCKyVmW6wxgBUHPZ3Tv4VvPaUslML0MaJAYdnySEHpD7OX4QTOPBLdgFlKfIL59yXY3x6lm8iIyqWwhw==",
      "miro-verification=3969bd74d34f4d6e10fb42f5233014d2d3dd4f9c",
      "mongodb-site-verification=P5bGlH3I0KYBkV7Lk3ZQPkLsXxb3QN4R",
      "google-site-verification=UORS-nc4KF2CsNXjoZmD3hLN9gvo3xdmmRXP2UE0N2Y",
      "google-site-verification=whYQbqxkVsb_xI5XKG3U8CQG2Vn75Nhx5HyTxo30gHA",
      "paloaltonetworks-site-verification=93e36781f48dc570d80205f59263b53045f9a982b7fcc747a23849d162298d7f"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:7675016f@in.mailhardener.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=redirect.xing.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "May  6 00:00:00 2026 GMT",
    "notAfter": "Nov 19 23:59:59 2026 GMT",
    "san": [
      "redirect.xing.com",
      "www.advertising-news.xing.com",
      "*.xingmodules.com",
      "*.openbc.de",
      "preview.api.whatsbroadcast.xing.com",
      "*.xing.de",
      "openbc.de",
      "www.bewerbung.com",
      "www.gehaltsindex.com",
      "*.whatsapp.xing.com",
      "*.xing.com",
      "xing.com",
      "*.coach.xing.com",
      "*.contaxt.de",
      "xing.de",
      "mail.new-work.se",
      "nwse.io",
      "contaxt.de",
      "preview.api.whatsapp.xing.com",
      "*.xing-video.com",
      "recruiting.xing.de",
      "xing.at",
      "*.xing.ch",
      "xingmodules.com",
      "gehaltsindex.com",
      "email.xing.com",
      "*.xn--jobbrse-d1a.com",
      "mail.xing.com",
      "lebenslauf.xn--jobbrse-d1a.com",
      "*.xing.at",
      "xing.io",
      "*.preview.xing.com",
      "xing.ch"
    ],
    "days_left": 54,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "18.154.144.107",
    "open": []
  },
  "https": {
    "status": 301,
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
      "origin": "https://sub.xing.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://xing.com/"
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
    "source": "certspotter",
    "count": 370,
    "notable": [
      "admin.preview.xing.com",
      "admin.xing.com",
      "api.ams1.xing.com",
      "api.ams2.xing.com",
      "api.preview.ams1.xing.com",
      "api.preview.ams2.xing.com",
      "api.preview.xing.com",
      "api.xing.com",
      "blog.xing.com",
      "dev.preview.xing.com",
      "dev.xing.com",
      "help.xing.com",
      "login.preview.xing.com",
      "login.xing.com",
      "mail.xing.com"
    ],
    "sample": [
      "200ok.preview.xing.com",
      "admin.preview.xing.com",
      "admin.xing.com",
      "adorable-bear.kenv.xing.com",
      "adorable-boar.kenv.xing.com",
      "adorable-elk.kenv.xing.com",
      "adorable-fox.kenv.xing.com",
      "adorable-goat.kenv.xing.com",
      "adorable-hippo.kenv.xing.com",
      "adorable-lion.kenv.xing.com",
      "adorable-rat.kenv.xing.com",
      "adorable-rhino.kenv.xing.com",
      "adorable-sheep.kenv.xing.com",
      "adorable-sloth.kenv.xing.com",
      "adorable-tiger.kenv.xing.com",
      "adorable-wolf.kenv.xing.com",
      "adorable-yak.kenv.xing.com",
      "adorable-zebra.kenv.xing.com",
      "ams1.xing.com",
      "ams2.xing.com"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=jC5_MqgVlYS7He0-uldAaB4z1uYxuZUKL_bTHaIYn-0",
    "atlassian-domain-verification=jQie6vPSfhfQ4wsCwYZtuCQTWC7PhDbv9HmrAzbRc6skBWWB/T",
    "facebook-domain-verification=xxd0q3s7lv62wywvvpver0e8j1j1vw",
    "google-site-verification=1CoJURTg2aHLa8bvDoNt_dDrLNmVPE93-cjaxYitSo8",
    "segment-site-verification=3fA98vkzGDmgoJbj3AG2CJvr8Z9mSQpx"
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
      "aia_ocsp": null,
      "not_before": "20260506000000",
      "not_after": "20261119235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/img/users",
      "/app/search",
      "/cgi-bin/search.fpl",
      "/patterns",
      "/jobs/posting_clicks",
      "/user-ass/jobs/posting_pdf",
      "/publicsearch/",
      "/search/",
      "/people/search/",
      "/r/",
      "/xbp/search",
      "/go/login",
      "/ads/",
      "/start/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "server-18-154-144-107.lax50.r.cloudfront.net."
    ]
  },
  "elapsed_s": 23.5,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
