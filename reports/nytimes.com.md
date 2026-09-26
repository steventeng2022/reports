# Security Audit Report — nytimes.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nytimes.com/ |
| Bug bounty program | The New York Times |
| Listed scope domain | nytimes.com |
| Test date | 2026-09-26 22:11 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 3, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 8 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 15 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 16 | info | CT1 | 88 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

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

### 7. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'nyt-gdpr' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 8. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'nyt-gdpr' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: parallels-domain-verification=df31386535ac4cbe8d70cde19722e58da9831b130c3d46299f; dropbox-domain-verification=4ld3jahx0psi; cursor-domain-verification-cbqk6b=DdvvVJNHMmVswd6oRmD8GZX50
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 150 disallow path(s), e.g. /ads/, /adx/bin/, /athletic/wp/wp-admin/, /athletic/async-*, /athletic/search/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of nytimes.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 15. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of nytimes.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 16. [INFO] 88 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: a.et.dev.nytimes.com, abra.api.nytimes.com, algo.dev.nytimes.com, api.nytimes.com, community.api.nytimes.com, community.api.stg.nytimes.com, cooking-admin.dev.nytimes.com, feast.ml.dev.nytimes.com, lb.a.purr.dev.nytimes.com, lire-ui-preview.auth.dev.nytimes.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "nytimes.com",
  "dns": {
    "a": [
      "151.101.65.164",
      "151.101.129.164",
      "151.101.193.164",
      "151.101.1.164"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "dns3.p06.nsone.net.",
      "ns-244.awsdns-30.com.",
      "ns-1652.awsdns-14.co.uk.",
      "ns-635.awsdns-15.net.",
      "dns4.p06.nsone.net.",
      "dns1.p06.nsone.net.",
      "ns-1328.awsdns-38.org.",
      "dns2.p06.nsone.net."
    ],
    "caa": [
      "0 issue \"amazon.com\"",
      "0 issue \"amazonaws.com\"",
      "0 issue \"amazontrust.com\"",
      "0 issue \"awstrust.com\"",
      "0 issue \"certainly.com\"",
      "0 issue \"comodoca.com\"",
      "0 issue \"digicert.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"pki.goog\"",
      "0 issue \"symantec.com\""
    ],
    "spf": [
      "v=spf1 include:nytimes.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:_spf.e.sparkpost.com include:amazonses.com ~all",
      "parallels-domain-verification=df31386535ac4cbe8d70cde19722e58da9831b130c3d46299f64ca5d0ed0f94d",
      "dropbox-domain-verification=4ld3jahx0psi",
      "ZOOM_verify_ClSSgAI2bqqZQA66rT4Z1x",
      "cursor-domain-verification-cbqk6b=DdvvVJNHMmVswd6oRmD8GZX50",
      "onetrust-domain-verification=1e62f8d767fc41a39fdf3f77025a8105",
      "klaviyo-site-verification=NsTtn9",
      "adobe-idp-site-verification=5ce4d99c-af0a-4b76-9217-bd49d3336df0",
      "lucidlink-verification=PZP4S4XGS2MW9TT3H76V0TPSY0",
      "_wufmw8f1leho148v35f8zaogcyux7lx",
      "docusign=bd506110-db79-430e-b159-cc1d74fe1176",
      "notion-domain-verification=4wS9fYEvnEgZg6Fc4cQ3atgsNuaj2zZIKwRP34uAGse",
      "253961548-4297453",
      "google-site-verification=4TE2ggBoy6PktLjtZ03t32A2oEZ0VD0PY6MnTj8IL_g",
      "onetrust-domain-verification=dee1266d6a984549b43a1bd101957a8f",
      "segment-site-verification=Z6wALFPYli6z0AlPlgjZXpMVRLZ2KiRb",
      "MS=A1BFCA84E21B7011CA98DF9DC251CDDF90E0174B",
      "atlassian-sending-domain-verification=1b4b110f-a2dd-4853-8b13-de36c831aa81",
      "_b2ao2yybjl1klqaw0mahepejqyvwgq1",
      "MS=ms22827202",
      "google-site-verification=dNxU4aqYrP-m9U4J4OO_hvaOfjepywv2BN8Luc-q4o8",
      "google-site-verification=NSmi94k0NzvQaksUCNXeJZPYtJPSoUf52cjJsJcZFy4",
      "jamf-site-verification=PIprfFrz8CBhH0TK0nNhnQ",
      "google-site-verification=OJl4BugQ_esE20V0QtVc9DhqvnnxOLHnf5AmFjdLSqk",
      "google-site-verification=ZTCMdpSKM7HwqTvGUf_00Ef008JhOnbzGgCSUGYfsro",
      "dell-technologies-domain-verification=nytimes.com_e9803e4c-210b-4501-a26b-705148cb7292_1777730473",
      "google-site-verification=tvhSn0gaSi6CUrrc9N1pvq4tmJrzvbfJbKVWPrgg_6Q",
      "masv=oFbRBdtBUCoWWHaQiRJLZcKASUJZboJz",
      "google-site-verification=NIqXa_F8IaqdPJhTtexgR0NYbzVLD_-X-uRUvyf4GyQ",
      "klaviyo-site-verification=VBhmML",
      "apple-domain-verification=1BVLidj37w9zRMnU",
      "google-site-verification=aReMr8hkX3gxeHLKKk4tJ1s970U7QdEqUMIhMmLUfjQ",
      "NV=6b9b6zcshr98ey1x",
      "miro-verification=ee856857f05022ca58c04ab6f8e4014e564b3d6b",
      "atlassian-domain-verification=Vrn33GZgJTapfeggl1snZZ5a8HjNwfFb1K5kBxVNhp7jlMFlRZGUytV9rIHhGdR8",
      "serval-domain-verification-bew4y4=VA1qmSGnvHaYCguEOONe1E2Nq",
      "google-site-verification=q5oM_szMOT79db0AJjdk_JP1xeurksaWmhbv_dd-MEM",
      "wrike-verification=NjYxMTMwODpmZGRiNmQ3Yjc1Yzk5NjFhMDk2OWI4MWM2NDhkZmYxNjdmOThhODQ2MDJmZmI0ZTMxNTUxOTMzZGRlMzQwZDEw",
      "gamma-domain-verification-m0hfp8=Kn1CNDywmVQvNK2EE60GxQORI",
      "wiz-domain-verification=f58277d3dd68296f29aace3a12b746a054eee9f6c472f21673207cfcc1991081",
      "google-site-verification=ZsySMeZ_SRbJZFu-53ptepytP7h5pxHO0qAg8Z2bKug",
      "docusign=6a4f88fd-cd2f-4917-acdb-bb2f343438a1",
      "shade-domain-verification-wys4jv=w07FFVQR3MSW3TNoXqZAYS7O0",
      "klaviyo-site-verification=PkxYaQ",
      "google-site-verification=jZcmQFxPEP38yqYpmRvo0v_9hQFAdBZPUEBwTNUPUF8",
      "google-site-verification=4qJm5sAZa1_29BTwFjqW09t7_7D4Vee3LBFQqg8xYbs"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email,mailto:dmarc.report@nytimes.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=nytimes.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=Thawte TLS RSA CA G1",
    "notBefore": "Sep  2 00:00:00 2026 GMT",
    "notAfter": "Mar 19 23:59:59 2027 GMT",
    "san": [
      "nytimes.com",
      "www.homedelivery.nytimes.com",
      "*.api.dev.nytimes.com",
      "*.api.nytimes.com",
      "*.api.stg.nytimes.com",
      "*.blogs.nytimes.com",
      "*.blogs.stg.nytimes.com",
      "*.dev.nyt.com",
      "*.dev.nyt.net",
      "*.dev.nytimes.com",
      "*.newsdev.nyt.net",
      "*.newsdev.nytimes.com",
      "*.nyt.com",
      "*.nyt.net",
      "*.nytco.com",
      "*.nytimes.com",
      "*.payflow.sbx.nytimes.com",
      "*.sbx.nytimes.com",
      "*.stg.newsdev.nyt.net",
      "*.stg.newsdev.nytimes.com",
      "*.stg.nyt.com",
      "*.stg.nyt.net",
      "*.stg.nytimes.com",
      "*.timestalks.com",
      "nyt.com",
      "nyt.net",
      "nytco.com",
      "timestalks.com",
      "*.myaccount-preview.stg.nytimes.com"
    ],
    "days_left": 174,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.65.164",
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
  "cookies": [
    {
      "domain": ".nytimes.com"
    },
    {
      "domain": ".nytimes.com",
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.nytimes.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://nytimes.com/"
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
    "count": 88,
    "notable": [
      "a.et.dev.nytimes.com",
      "abra.api.nytimes.com",
      "algo.dev.nytimes.com",
      "api.nytimes.com",
      "community.api.nytimes.com",
      "community.api.stg.nytimes.com",
      "cooking-admin.dev.nytimes.com",
      "feast.ml.dev.nytimes.com",
      "lb.a.purr.dev.nytimes.com",
      "lire-ui-preview.auth.dev.nytimes.com",
      "mes-user.api.dev.nytimes.com",
      "mes-user.api.nytimes.com",
      "mes-user.api.stg.nytimes.com",
      "messaging-sub.api.nytimes.com",
      "ml.dev.nytimes.com"
    ],
    "sample": [
      "a.et.dev.nytimes.com",
      "a.et.nytimes.com",
      "a.et.stg.nytimes.com",
      "abra.api.nytimes.com",
      "abra.nytimes.com",
      "account-int.stg.nytimes.com",
      "advertising.nytimes.com",
      "aiqpost.nytimes.com",
      "algo.dev.nytimes.com",
      "algo.stg.nytimes.com",
      "als-svc.nytimes.com",
      "api.nytimes.com",
      "appdata.i.cn.nytimes.com",
      "bestsellers.nytimes.com",
      "cn.nytimes.com",
      "community.api.nytimes.com",
      "community.api.stg.nytimes.com",
      "cooking-admin.dev.nytimes.com",
      "cooking-admin.em.nytimes.com",
      "cooking-admin.stg.nytimes.com"
    ]
  },
  "apex_txt": [
    "parallels-domain-verification=df31386535ac4cbe8d70cde19722e58da9831b130c3d46299f",
    "dropbox-domain-verification=4ld3jahx0psi",
    "cursor-domain-verification-cbqk6b=DdvvVJNHMmVswd6oRmD8GZX50",
    "onetrust-domain-verification=1e62f8d767fc41a39fdf3f77025a8105",
    "klaviyo-site-verification=NsTtn9"
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
      "aia_ocsp": "http://status.thawte.com",
      "not_before": "20260902000000",
      "not_after": "20270319235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/ads/",
      "/adx/bin/",
      "/athletic/wp/wp-admin/",
      "/athletic/async-*",
      "/athletic/search/*",
      "/athletic/checkout/",
      "/athletic/checkout?plan_id*",
      "/athletic/checkout2*",
      "/athletic/login/",
      "/athletic/login?login_source*",
      "/athletic/login?ref_page*",
      "/athletic/login2/",
      "/athletic/login2?login_source*",
      "/athletic/login2?ref_page*",
      "/athletic/report/"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.nytimes.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 19.1,
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
