# Security Audit Report — vimeo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vimeo.com/ |
| Bug bounty program | Vimeo |
| Listed scope domain | vimeo.com |
| Test date | 2026-09-26 22:17 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 1, Info: 17)

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
| 16 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 17 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 18 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |

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
- **Detail:** Apex TXT records with verification/token content: dropbox-domain-verification=i3wbe0w3wzci; google-site-verification=hMdG7S08M7DLvcHiWDzVzvXxZUsfkruKr0Uo_oCLO0Y; stripe-verification=E1C768C81651F3AB136567486779A84AAA7BFB9BB069E433B6D2D9396FAD
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of vimeo.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 357 disallow path(s), e.g. /*/format:thumbnail, /download/, /*/download?, /couchmode/, /groups/*/forum/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on vimeo.com indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 17. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xk5u26ey07genm.html -> 404; error page/headers match: Cloudflare.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 18. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on vimeo.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

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
      "aspmx2.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-1886.awsdns-43.co.uk.",
      "ns-1463.awsdns-54.org.",
      "ns-682.awsdns-21.net.",
      "ns-70.awsdns-08.com."
    ],
    "caa": [
      "0 issuewild \"digicert.com\"",
      "0 issue \"globalsign.com\"",
      "0 issuewild \"letsencrypt.org\"",
      "0 issuewild \"pki.goog; cansignhttpexchanges=yes\"",
      "0 issue \"pki.goog; cansignhttpexchanges=yes\"",
      "0 issuewild \"globalsign.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"amazon.com\"",
      "0 issue \"digicert.com\""
    ],
    "spf": [
      "MS=ms31258684",
      "dropbox-domain-verification=i3wbe0w3wzci",
      "MS=ms11883597",
      "google-site-verification=hMdG7S08M7DLvcHiWDzVzvXxZUsfkruKr0Uo_oCLO0Y",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:mail.zendesk.com include:helpscoutemail.com include:mktomail.com ~all",
      "stripe-verification=E1C768C81651F3AB136567486779A84AAA7BFB9BB069E433B6D2D9396FAD8E69",
      "apple-domain-verification=hqseHhrDZs9mvnIu",
      "stripe-verification=0905bcb5e5ed859c59ffac03f0580752c43adbd9282bb40aa1d68b6f93742a43",
      "stripe-verification=8f5465c02af6b9e2739d83ed01d0231504d39f845e6ab2c500ebe9fa5884934c",
      "hubspot-developer-verification=NWMyOWIzNzAtNWUwNS00MjVlLTlkMjMtYmIyYmY5YzczNTk3",
      "adobe-idp-site-verification=2b3f171733f9ec79ece6f6deb429f4f4ddf5d3df3e66bf5460e040eb4489cb50",
      "docker-verification=bc8a3b85-f3de-4303-a77b-5963968dd27d",
      "_globalsign-domain-verification=-ogVhboN12TmJn3fnj8AgBTj2LhZkXy26R2M6hIT_Q",
      "stripe-verification=515b72a65b4832050e6f4076d2db128f4e88520c3b5fb553475b1df83fdb32e9",
      "zoho-verification=zb15890134.zmverify.zoho.com",
      "google-site-verification=e8qUoscBYD-sPanSS-r0dcYo9EaoIBbLBoyMaBv3sKg",
      "stripe-verification=9C62CFA25412CCA90EEFA2F73D0FAB0569988DAE456E14993A808C05DEBAA460",
      "notion-domain-verification=1PLl3PgY3bgqYvCAzWFbUF99iW9phzauRb9FYvzQPIa",
      "google-site-verification=UYx7dBka_Zr85ae_GcZlDBs_FkRo3loBwU3GDL0rXkA",
      "anthropic-domain-verification-c7xc4h=EA7RDQhcYq3danVfSx0B3iMRY",
      "atlassian-domain-verification=OQUW8wO6JYgjdHThsMyRzUbqCNuYUJ1qA4ryjBsCIcdOFxvr5pFrW4Dt27ZDhLRq",
      "stripe-verification=c63db8272ec91b68ebacdbe0526f7f976eb7cf5907ce4f45ea6bca970a33659d",
      "canva-site-verification=DQAQJSZSFIPE9wLghNGucA",
      "google-site-verification=RcUDKcVx4BFOK12yi3crRyHO0A4ys1NdWSC-q5pA0Aw",
      "stripe-verification=ba8501efece26680bae276979f5c24f1248cc3ca389b87a1c20889cec54438b4",
      "stripe-verification=9d282334c83ec1bad81c10522b09ecbe5ab60b559747c606f318bc4071a7899e",
      "MS=ms50463091",
      "pendo-domain-verification=6b8dfe6a-b123-4af8-a9d1-34f905d0d913",
      "ca3-c918c5d16cb8495caffedfd48de3b949",
      "_x7awpslobtj17k90mhi3bdsfn4fpiqg",
      "yilRhWU2gaWPjUDNJn7Jzxym+9x0hezYabN6SdN0jgD6pU1GgIjgsbqxpR9VIAzo/zsaOf9UCfGqqG0J6onbIw==",
      "amazonses:aG3MHmiDMfK+ROMMdC2TI3pgSqB/irrc/EffhZm8fpY=",
      "parallels-domain-verification=6074395df5334b55afeea25a7a158ad484372217232842ebb488297a740e23c1",
      "notion-domain-verification=qP73sg1oSUsNT1z0kwxX7qZrqGtWyBWVW39BmrJzRfp",
      "_globalsign-domain-verification=u43aixYwit_P_nZo8n15y__KZcxnZCg08KEe5iho2D",
      "stripe-verification=8c8a6dfe7831b0d791528fb81c0f1302f0d2919a5cce9e455045feb2dda61868",
      "elevenlabs=lagWi04NXUqluH6Z_aJOSAmqqdwRbGllJxQhDj9r1ec",
      "sending_domain1125061=22ff236a83e1d42acb8bf0bb257fce1e87eb4b9f3967a3167bf55da342f56f7d",
      "google-site-verification=-eOb-DlXc3e9Qy6WVinkTxCyRa0MtgCqrlMMtRcyEa8",
      "834wn8161vj1q0sw515h2p3pkc3nwwpy",
      "mosyle-verification-326584517",
      "facebook-domain-verification=m3jcqq4qg23ihpjh5w5x5iswpyg6by",
      "google-site-verification=hvy1Rpbhxy-S65t34-vb8qhUKGvEGtfPBciS1TQMl3M",
      "_croefc07jkoevgoq7ho4k23j9guzq3t",
      "openai-domain-verification=dv-jLpzDoIthu5YP30T9S28cHgn",
      "smartsheet-site-validation=Z_Zhh94Jn680XCzJ92bQI72bIBCat5Vw",
      "hs-m4HC9yjhxb9JdEsZisAQJEx6",
      "google-site-verification=henfs-vWflKItEV28eNNiXdcPPLeB8FAkluqr0wm4i0",
      "jamf-site-verification=Ok9tNLMbaiTgFfGONT6keA",
      "brave-ledger-verification=ea3ce87b613b3706879f8d5c90b564eaa08b31e0d1c1bd59175aa394ef7c8c63",
      "pardot1125061=5dc9fc1db14d4ab197d6d920f4b106693801c1989a52face12b1d76675cfd922",
      "jetbrains-domain-verification=3ng8i2b2sjr1ojnpfa4akr6ry",
      "mongodb-site-verification=SMYuJ9hNJ78bA03BaqnO5p8HrRn5pnIx"
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
    "dropbox-domain-verification=i3wbe0w3wzci",
    "google-site-verification=hMdG7S08M7DLvcHiWDzVzvXxZUsfkruKr0Uo_oCLO0Y",
    "stripe-verification=E1C768C81651F3AB136567486779A84AAA7BFB9BB069E433B6D2D9396FAD",
    "apple-domain-verification=hqseHhrDZs9mvnIu",
    "stripe-verification=0905bcb5e5ed859c59ffac03f0580752c43adbd9282bb40aa1d68b6f9374"
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
      "not_before": "20260903122717",
      "not_after": "20261202132658"
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
  "x12": {
    "status": 200
  },
  "x13": {
    "root_status": 200,
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
  "elapsed_s": 9.8,
  "rechecked": "2026-09-26 21:56 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- Findings are reported against the public program scope; submission through the program tracker is pending.
