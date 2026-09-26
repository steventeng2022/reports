# Security Audit Report — paypal.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://paypal.com/ |
| Bug bounty program | PayPal |
| Listed scope domain | paypal.com |
| Test date | 2026-09-26 18:57 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 5, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 19 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 20 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.141.96:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.141.96:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=300 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 11. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): pp., 3ph1., 3ph2., 3ph3. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 15. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 16. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: workplace-domain-verification=F7ezsH9uapvYDGd2VtPARy1qq9ymN6; adobe-idp-site-verification=11600efbec96c0e73dd8820cd33ca906ec4302aea4487d208a42; stripe-verification=549bef27619f14f935a84c6a23492e80f49ff57a341d9ddc74d8486881cd
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of paypal.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 19. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 92 disallow path(s), e.g. /cgibin/, /il/cart/, /*?cmd=_pce*, /row/, /xclick-auction*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 20. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://paypal.com/ carries Cache-Control: max-age=86400; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

## Evidence (raw response observations)

```json
{
  "domain": "paypal.com",
  "dns": {
    "a": [
      "162.159.141.96",
      "151.101.195.1",
      "151.101.3.1"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx2.paypalcorp.com (pref 10)",
      "mx1.paypalcorp.com (pref 10)"
    ],
    "ns": [
      "ns1-pchnet.paypal.com.",
      "ns2-pchnet.paypal.com.",
      "pdns100.ultradns.com.",
      "pdns100.ultradns.net."
    ],
    "spf": [
      "workplace-domain-verification=F7ezsH9uapvYDGd2VtPARy1qq9ymN6",
      "adobe-idp-site-verification=11600efbec96c0e73dd8820cd33ca906ec4302aea4487d208a42a2b01806144c",
      "stripe-verification=549bef27619f14f935a84c6a23492e80f49ff57a341d9ddc74d8486881cd0d8c",
      "mgverify=e00c4bf7480ee22be851faa9acd20e41b8fd0f7b75b434bbe38aa257e5aae3a0",
      "mgf84gx1cv1c759pmjqx0wnths9ss9f6",
      "v=spf1 include:pp._spf.paypal.com include:3ph1._spf.paypal.com include:3ph2._spf.paypal.com include:3ph3._spf.paypal.com include:3ph4._spf.paypal.com include:sendgrid.net include:aspmx.pardot.com ~all",
      "docker-verification=2deb3c1f-56d2-4fe4-8a09-d48b7bf8a918",
      "MS=ms95960309",
      "globalsign-domain-verification=KXa3jn_dNODlTVQ4eg1Wx3vA-RrHZ2K7iLQN0vdJBx",
      "atlassian-domain-verification=Q8BdHlO6NYSN5njfC2rlbPQxksVfADlcxarxq4fesYJErtGKylvfcfyfwrPD/wnv",
      "Notion_verify_uVqjH2PpjVthR9xxfR5BZGsuYGtqb6Za4uDHPaA917v5Cg5J0rRwiATz84PWHZh8Px7vFK",
      "intersight=6d86ec09a7c6926c6f9b8eff8ef0ef06679d84aab4999756a0920a8d430ed8ae"
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
    "cipher": "TLS_AES_256_GCM_SHA384",
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
    "ip": "162.159.141.96",
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
    "workplace-domain-verification=F7ezsH9uapvYDGd2VtPARy1qq9ymN6",
    "adobe-idp-site-verification=11600efbec96c0e73dd8820cd33ca906ec4302aea4487d208a42",
    "stripe-verification=549bef27619f14f935a84c6a23492e80f49ff57a341d9ddc74d8486881cd",
    "docker-verification=2deb3c1f-56d2-4fe4-8a09-d48b7bf8a918",
    "globalsign-domain-verification=KXa3jn_dNODlTVQ4eg1Wx3vA-RrHZ2K7iLQN0vdJBx"
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
      "not_before": "20260511000000",
      "not_after": "20261125235959"
    }
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
  "elapsed_s": 14.4,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
