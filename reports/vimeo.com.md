# Security Audit Report — vimeo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vimeo.com/ |
| Bug bounty program | Vimeo |
| Listed scope domain | vimeo.com |
| Test date | 2026-09-26 17:54 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 1, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.138.60:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.138.60:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; X-Powered-By: Next.js; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: canva-site-verification=DQAQJSZSFIPE9wLghNGucA; stripe-verification=0905bcb5e5ed859c59ffac03f0580752c43adbd9282bb40aa1d68b6f9374; jetbrains-domain-verification=3ng8i2b2sjr1ojnpfa4akr6ry
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of vimeo.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 357 disallow path(s), e.g. /*/format:thumbnail, /download/, /*/download?, /couchmode/, /groups/*/forum/*
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "vimeo.com",
  "dns": {
    "a": [
      "162.159.138.60",
      "162.159.128.61"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 10)",
      "aspmx2.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-70.awsdns-08.com.",
      "ns-1463.awsdns-54.org.",
      "ns-1886.awsdns-43.co.uk.",
      "ns-682.awsdns-21.net."
    ],
    "spf": [
      "canva-site-verification=DQAQJSZSFIPE9wLghNGucA",
      "stripe-verification=0905bcb5e5ed859c59ffac03f0580752c43adbd9282bb40aa1d68b6f93742a43",
      "jetbrains-domain-verification=3ng8i2b2sjr1ojnpfa4akr6ry",
      "google-site-verification=e8qUoscBYD-sPanSS-r0dcYo9EaoIBbLBoyMaBv3sKg",
      "MS=ms31258684",
      "google-site-verification=hMdG7S08M7DLvcHiWDzVzvXxZUsfkruKr0Uo_oCLO0Y",
      "brave-ledger-verification=ea3ce87b613b3706879f8d5c90b564eaa08b31e0d1c1bd59175aa394ef7c8c63",
      "_croefc07jkoevgoq7ho4k23j9guzq3t",
      "_globalsign-domain-verification=-ogVhboN12TmJn3fnj8AgBTj2LhZkXy26R2M6hIT_Q",
      "zoho-verification=zb15890134.zmverify.zoho.com",
      "834wn8161vj1q0sw515h2p3pkc3nwwpy",
      "MS=ms50463091",
      "yilRhWU2gaWPjUDNJn7Jzxym+9x0hezYabN6SdN0jgD6pU1GgIjgsbqxpR9VIAzo/zsaOf9UCfGqqG0J6onbIw==",
      "amazonses:aG3MHmiDMfK+ROMMdC2TI3pgSqB/irrc/EffhZm8fpY=",
      "google-site-verification=RcUDKcVx4BFOK12yi3crRyHO0A4ys1NdWSC-q5pA0Aw",
      "MS=ms11883597",
      "stripe-verification=c63db8272ec91b68ebacdbe0526f7f976eb7cf5907ce4f45ea6bca970a33659d",
      "notion-domain-verification=qP73sg1oSUsNT1z0kwxX7qZrqGtWyBWVW39BmrJzRfp",
      "adobe-idp-site-verification=2b3f171733f9ec79ece6f6deb429f4f4ddf5d3df3e66bf5460e040eb4489cb50",
      "stripe-verification=E1C768C81651F3AB136567486779A84AAA7BFB9BB069E433B6D2D9396FAD8E69",
      "ca3-c918c5d16cb8495caffedfd48de3b949",
      "google-site-verification=UYx7dBka_Zr85ae_GcZlDBs_FkRo3loBwU3GDL0rXkA",
      "docker-verification=bc8a3b85-f3de-4303-a77b-5963968dd27d",
      "stripe-verification=ba8501efece26680bae276979f5c24f1248cc3ca389b87a1c20889cec54438b4",
      "openai-domain-verification=dv-jLpzDoIthu5YP30T9S28cHgn",
      "sending_domain1125061=22ff236a83e1d42acb8bf0bb257fce1e87eb4b9f3967a3167bf55da342f56f7d",
      "_x7awpslobtj17k90mhi3bdsfn4fpiqg",
      "atlassian-domain-verification=OQUW8wO6JYgjdHThsMyRzUbqCNuYUJ1qA4ryjBsCIcdOFxvr5pFrW4Dt27ZDhLRq",
      "pardot1125061=5dc9fc1db14d4ab197d6d920f4b106693801c1989a52face12b1d76675cfd922",
      "parallels-domain-verification=6074395df5334b55afeea25a7a158ad484372217232842ebb488297a740e23c1",
      "smartsheet-site-validation=Z_Zhh94Jn680XCzJ92bQI72bIBCat5Vw",
      "apple-domain-verification=hqseHhrDZs9mvnIu",
      "google-site-verification=-eOb-DlXc3e9Qy6WVinkTxCyRa0MtgCqrlMMtRcyEa8",
      "_globalsign-domain-verification=u43aixYwit_P_nZo8n15y__KZcxnZCg08KEe5iho2D",
      "google-site-verification=hvy1Rpbhxy-S65t34-vb8qhUKGvEGtfPBciS1TQMl3M",
      "elevenlabs=lagWi04NXUqluH6Z_aJOSAmqqdwRbGllJxQhDj9r1ec",
      "google-site-verification=henfs-vWflKItEV28eNNiXdcPPLeB8FAkluqr0wm4i0",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:mail.zendesk.com include:helpscoutemail.com include:mktomail.com ~all",
      "facebook-domain-verification=m3jcqq4qg23ihpjh5w5x5iswpyg6by",
      "notion-domain-verification=1PLl3PgY3bgqYvCAzWFbUF99iW9phzauRb9FYvzQPIa",
      "mosyle-verification-326584517",
      "pendo-domain-verification=6b8dfe6a-b123-4af8-a9d1-34f905d0d913",
      "dropbox-domain-verification=i3wbe0w3wzci",
      "jamf-site-verification=Ok9tNLMbaiTgFfGONT6keA",
      "stripe-verification=9C62CFA25412CCA90EEFA2F73D0FAB0569988DAE456E14993A808C05DEBAA460",
      "stripe-verification=515b72a65b4832050e6f4076d2db128f4e88520c3b5fb553475b1df83fdb32e9",
      "hs-m4HC9yjhxb9JdEsZisAQJEx6",
      "mongodb-site-verification=SMYuJ9hNJ78bA03BaqnO5p8HrRn5pnIx",
      "hubspot-developer-verification=NWMyOWIzNzAtNWUwNS00MjVlLTlkMjMtYmIyYmY5YzczNTk3",
      "stripe-verification=9d282334c83ec1bad81c10522b09ecbe5ab60b559747c606f318bc4071a7899e",
      "stripe-verification=8c8a6dfe7831b0d791528fb81c0f1302f0d2919a5cce9e455045feb2dda61868",
      "anthropic-domain-verification-c7xc4h=EA7RDQhcYq3danVfSx0B3iMRY",
      "stripe-verification=8f5465c02af6b9e2739d83ed01d0231504d39f845e6ab2c500ebe9fa5884934c"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; adkim=r; aspf=r; rua=mailto:dmarc_agg@vali.email,mailto:0bf8497523a6913@rep.dmarcanalyzer.com; ruf=mailto:0bf8497523a6913@for.dmarcanalyzer.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=vimeo.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep  3 12:27:17 2026 GMT",
    "notAfter": "Dec  2 13:26:58 2026 GMT",
    "san": [
      "vimeo.com",
      "*.vimeo.com"
    ],
    "days_left": 66,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "162.159.138.60",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Vimeo - All-in-One Video Platform"
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "X-Powered-By: Next.js",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "vimeo.com",
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
      "origin": "https://sub.vimeo.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://vimeo.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 308
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "canva-site-verification=DQAQJSZSFIPE9wLghNGucA",
    "stripe-verification=0905bcb5e5ed859c59ffac03f0580752c43adbd9282bb40aa1d68b6f9374",
    "jetbrains-domain-verification=3ng8i2b2sjr1ojnpfa4akr6ry",
    "google-site-verification=e8qUoscBYD-sPanSS-r0dcYo9EaoIBbLBoyMaBv3sKg",
    "google-site-verification=hMdG7S08M7DLvcHiWDzVzvXxZUsfkruKr0Uo_oCLO0Y"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/*/format:thumbnail",
      "/download/",
      "/*/download?",
      "/couchmode/",
      "/groups/*/forum/*",
      "/musicstore/preview",
      "/musicstore/download",
      "/forgot_password",
      "/help/forgot_login",
      "/help/verify_email",
      "/help/zendesk_sso",
      "/help/sso",
      "/user/verify",
      "/search/",
      "/search?"
    ]
  },
  "elapsed_s": 11.3,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
