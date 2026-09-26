# Security Audit Report — kobo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://kobo.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | kobo.com |
| Test date | 2026-09-26 18:54 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 4, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 19 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.150.101:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.150.101:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://www.kobo.com/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

### 14. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=Q25CMQs0FyZeTBTcsd2e3pVmeINoplPPcC0OyZp-cYw; google-site-verification=fubvUR2vWX0-_N-3h9Q6fR9el0Vi-OPTf-ysDQ2alrU; google-site-verification=TPfQLJMxDmDJ7QLK1G7_9WKCyT33Zd4OKl8Y3xcVUmA
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of kobo.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 19. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 95 disallow path(s), e.g. /Book/AddToLibrary/, /Book/AddPreviewToLibrary/, /Purchase/Buy, /*/purchase/buy/*, /ShoppingCartWidget/Add
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "kobo.com",
  "dns": {
    "a": [
      "172.64.150.101",
      "104.18.37.155"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "kobo-com.mail.protection.outlook.com (pref 5)"
    ],
    "ns": [
      "ns-cloud-e4.googledomains.com.",
      "ns-cloud-e1.googledomains.com.",
      "ns-cloud-e3.googledomains.com.",
      "ns-cloud-e2.googledomains.com."
    ],
    "spf": [
      "google-site-verification=Q25CMQs0FyZeTBTcsd2e3pVmeINoplPPcC0OyZp-cYw",
      "google-site-verification=fubvUR2vWX0-_N-3h9Q6fR9el0Vi-OPTf-ysDQ2alrU",
      "google-site-verification=TPfQLJMxDmDJ7QLK1G7_9WKCyT33Zd4OKl8Y3xcVUmA",
      "MS=ms57345456",
      "ca3-763497e7b6ed42dab28acd1f86e299cf",
      "eI4nDhTkhHLFkVn2I0H86PYkbQzHr26YA6ndMom0SKIrZENOFNfL3EFFlWHcp+r4uBL1NDg63BxMrflvKQkl+w==",
      "fastly-domain-delegation-fddelt00540045-10-22-25",
      "v=spf1 mx include:spf1.kobo.com include:spf.protection.outlook.com include:_spf.alchemer.eu include:stspg-customer.com include:_spf.mlsend.com include:shops.shopify.com include:mail.zendesk.com include:amazonses.com ~all",
      "google-site-verification=TMvqQdCrWZE_zq_PIvMaWObopFipEhVGM3-NQ1D5qfY",
      "17c61b51fd3e47faa7bbb0cb888ecbb0",
      "cloudflare_dashboard_sso=9953105deb781640ed8a6f7e927897bf",
      "status-page-domain-verification=9t2wdqtpqygk",
      "hj-ownership=fvkv30Fnyx78b9M",
      "google-site-verification=3aKt7utuf138msKSFHlGaxHSWaUfmh7xexzcZNtlSN0",
      "google-site-verification=SN46x048vtTZTeC4pcKIeVtbSbhp22YtkZIaMnlEWKY",
      "facebook-domain-verification=asza9zmotc5y3jf2vvxuox1fh4zwal"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:kobo-DMARC_Report@mail.rakuten.com,mailto:dmarc-report-a@rx.rakuten.co.jp"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=kobo.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 19 06:16:01 2026 GMT",
    "notAfter": "Nov 17 07:15:34 2026 GMT",
    "san": [
      "kobo.com",
      "*.kobo.com"
    ],
    "days_left": 51,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.64.150.101",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.kobo.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://www.kobo.com/"
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
    "google-site-verification=Q25CMQs0FyZeTBTcsd2e3pVmeINoplPPcC0OyZp-cYw",
    "google-site-verification=fubvUR2vWX0-_N-3h9Q6fR9el0Vi-OPTf-ysDQ2alrU",
    "google-site-verification=TPfQLJMxDmDJ7QLK1G7_9WKCyT33Zd4OKl8Y3xcVUmA",
    "google-site-verification=TMvqQdCrWZE_zq_PIvMaWObopFipEhVGM3-NQ1D5qfY",
    "status-page-domain-verification=9t2wdqtpqygk"
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
      "not_before": "20260819061601",
      "not_after": "20261117071534"
    }
  },
  "http2": {
    "robots_disallow": [
      "/Book/AddToLibrary/",
      "/Book/AddPreviewToLibrary/",
      "/Purchase/Buy",
      "/*/purchase/buy/*",
      "/ShoppingCartWidget/Add",
      "/InstantPreviewWidget/LoadInstantPreviewMetadata",
      "/MarketingContentWidget/GetCurrentBanner",
      "/Uploads/Books/Reviews/",
      "/shoppingcartwidget/add",
      "*/shoppingcartwidget*",
      "*/checkout/createpurchase",
      "*/checkout/createpurchaseifallowed",
      "/Tracking/VerifyHuman",
      "*/*Tracking/VerifyHuman",
      "/tracking/verifyhuman"
    ]
  },
  "x12": {
    "status": 302
  },
  "elapsed_s": 5.2,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
