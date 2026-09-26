# Security Audit Report — paypal.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://paypal.com/ |
| Bug bounty program | PayPal |
| Listed scope domain | paypal.com |
| Test date | 2026-09-26 22:12 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 5, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 18 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=300 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): pp., 3ph1., 3ph2., 3ph3. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

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
- **Detail:** Apex TXT records with verification/token content: adobe-idp-site-verification=11600efbec96c0e73dd8820cd33ca906ec4302aea4487d208a42; stripe-verification=549bef27619f14f935a84c6a23492e80f49ff57a341d9ddc74d8486881cd; workplace-domain-verification=F7ezsH9uapvYDGd2VtPARy1qq9ymN6
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 92 disallow path(s), e.g. /cgibin/, /il/cart/, /*?cmd=_pce*, /row/, /xclick-auction*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://paypal.com/ carries Cache-Control: max-age=86400; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 18. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on paypal.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

## Evidence (raw response observations)

```json
{
  "domain": "paypal.com",
  "dns": {
    "a": [
      "151.101.3.1",
      "162.159.141.96",
      "151.101.195.1"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx1.paypalcorp.com (pref 10)",
      "mx2.paypalcorp.com (pref 10)"
    ],
    "ns": [
      "ns1-pchnet.paypal.com.",
      "ns2-pchnet.paypal.com.",
      "pdns100.ultradns.com.",
      "pdns100.ultradns.net."
    ],
    "caa": [
      "0 issue \"digicert.com\"",
      "0 issue \"quovadisglobal.com\"",
      "0 issue \"visa.com\""
    ],
    "spf": [
      "adobe-idp-site-verification=11600efbec96c0e73dd8820cd33ca906ec4302aea4487d208a42a2b01806144c",
      "v=spf1 include:pp._spf.paypal.com include:3ph1._spf.paypal.com include:3ph2._spf.paypal.com include:3ph3._spf.paypal.com include:3ph4._spf.paypal.com include:sendgrid.net include:aspmx.pardot.com ~all",
      "stripe-verification=549bef27619f14f935a84c6a23492e80f49ff57a341d9ddc74d8486881cd0d8c",
      "intersight=6d86ec09a7c6926c6f9b8eff8ef0ef06679d84aab4999756a0920a8d430ed8ae",
      "mgf84gx1cv1c759pmjqx0wnths9ss9f6",
      "mgverify=e00c4bf7480ee22be851faa9acd20e41b8fd0f7b75b434bbe38aa257e5aae3a0",
      "workplace-domain-verification=F7ezsH9uapvYDGd2VtPARy1qq9ymN6",
      "docker-verification=2deb3c1f-56d2-4fe4-8a09-d48b7bf8a918",
      "atlassian-domain-verification=Q8BdHlO6NYSN5njfC2rlbPQxksVfADlcxarxq4fesYJErtGKylvfcfyfwrPD/wnv",
      "Notion_verify_uVqjH2PpjVthR9xxfR5BZGsuYGtqb6Za4uDHPaA917v5Cg5J0rRwiATz84PWHZh8Px7vFK",
      "MS=ms95960309",
      "globalsign-domain-verification=KXa3jn_dNODlTVQ4eg1Wx3vA-RrHZ2K7iLQN0vdJBx"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com,mailto:dmarc_agg@vali.email; ruf=mailto:d@ruf.agari.com,mailto:MTc4Mzcw@ruf.vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Jose, organizationName=PayPal, Inc., commonName=paypal.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "May 11 00:00:00 2026 GMT",
    "notAfter": "Nov 25 23:59:59 2026 GMT",
    "san": [
      "paypal.com",
      "braintreepayments.com",
      "buyindiaonline.com",
      "cash2india.com",
      "curv.cc",
      "curv.co",
      "fastlane.paypal.com",
      "paypal-australia.com.au",
      "paypal-business.co.uk",
      "paypal-business.com.au",
      "paypal-businesscenter.com",
      "paypal-communications.com",
      "paypal-corp.com",
      "paypal-danmark.dk",
      "PAYPAL-DEUTSCHLAND.DE",
      "paypal-donations.co.uk",
      "paypal-donations.com",
      "paypal-experience.com",
      "paypal-gifts.com",
      "paypal-globalshops.com",
      "paypal-information.com",
      "paypal-knowledge-test.com",
      "paypal-knowledge.com",
      "paypal-latam.com",
      "paypal-marketing.ca",
      "paypal-marketing.co.uk",
      "PAYPAL-MARKETING.PL",
      "paypal-media.com",
      "paypal-mena.com",
      "paypal-mktg.com",
      "paypal-nakit.com",
      "paypal-norge.no",
      "paypal-optimizer.com",
      "paypal-partners.com",
      "paypal-passport.com",
      "paypal-prepagata.com",
      "paypal-promo.es",
      "paypal-support.com",
      "paypal-sverige.se",
      "paypal-turkiye.com",
      "paypal-workplace.com",
      "paypal.ai",
      "paypal.at",
      "paypal.be",
      "paypal.biz",
      "paypal.ca",
      "paypal.ch",
      "paypal.cl",
      "PAYPAL.CO",
      "paypal.co.id",
      "paypal.co.il",
      "paypal.co.in",
      "paypal.co.nz",
      "paypal.co.th",
      "paypal.co.uk",
      "paypal.co.za",
      "paypal.com.ar",
      "paypal.com.au",
      "paypal.com.br",
      "paypal.com.cn",
      "paypal.com.hk",
      "paypal.com.mx",
      "PAYPAL.COM.MY",
      "paypal.com.pe",
      "paypal.com.sa",
      "paypal.com.sg",
      "paypal.com.tr",
      "paypal.com.tw",
      "paypal.com.ve",
      "paypal.de",
      "paypal.dk",
      "paypal.es",
      "paypal.eu",
      "paypal.fi",
      "paypal.fr",
      "paypal.ie",
      "paypal.in",
      "paypal.it",
      "paypal.jp",
      "paypal.lu",
      "paypal.me",
      "paypal.nl",
      "paypal.no",
      "paypal.ph",
      "paypal.pl",
      "paypal.pt",
      "paypal.se",
      "paypal.vn",
      "paypalbenefits.com",
      "paypalgivingfund.org",
      "paypalobjects.com",
      "pypl.com",
      "sandbox.paypal.com",
      "simility.com",
      "thepaypalblog.com",
      "www.curv.cc",
      "www.curv.co",
      "www.paypal.ai",
      "www.paypal.biz",
      "www.paypal.com",
      "www.simility.com",
      "xoom.com"
    ],
    "days_left": 60,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.3.1",
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
      "acac": ""
    },
    {
      "origin": "https://sub.paypal.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://paypal.com/"
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
    "adobe-idp-site-verification=11600efbec96c0e73dd8820cd33ca906ec4302aea4487d208a42",
    "stripe-verification=549bef27619f14f935a84c6a23492e80f49ff57a341d9ddc74d8486881cd",
    "workplace-domain-verification=F7ezsH9uapvYDGd2VtPARy1qq9ymN6",
    "docker-verification=2deb3c1f-56d2-4fe4-8a09-d48b7bf8a918",
    "atlassian-domain-verification=Q8BdHlO6NYSN5njfC2rlbPQxksVfADlcxarxq4fesYJErtGKyl"
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
      "not_before": "20260511000000",
      "not_after": "20261125235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/cgibin/",
      "/il/cart/",
      "/*?cmd=_pce*",
      "/row/",
      "/xclick-auction*",
      "/affil/",
      "/*?cmd=_flow*",
      "/*?cmd=_mobile-activate-outside",
      "/*?SESSION*",
      "/*?cmd=_s-xclick*",
      "/subscriptions/",
      "/ireceipt/get/",
      "/ireceipt/get?",
      "/getCallUsInfoData/",
      "/*?action=callus"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.paypal.com/",
    "http_status": 301,
    "p404_status": 301,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 17.1,
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
