# Security Audit Report — aliexpress.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://aliexpress.com/ |
| Bug bounty program | Alibaba |
| Listed scope domain | aliexpress.com |
| Test date | 2026-09-26 18:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 8, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 12 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 13 | low | CORS3 | CORS: external origin accepted with credentials | CWE-942 |
| 14 | low | CORS1 | CORS: subdomain origin origin accepted with credentials | CWE-942 |
| 15 | info | P6 | phpMyAdmin endpoint reachable | CWE-200 |
| 16 | info | P8 | Missing security.txt | CWE-1038 |
| 17 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 18 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 19 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 20 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 21 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 22 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Tengine/AServer-Ingress
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: Tengine/AServer-Ingress
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'x5secdata' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 12. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'x5secdata' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 13. [LOW] CORS: external origin accepted with credentials (`CORS3`)

- **CWE:** CWE-942
- **Detail:** Origin https://evil-auditor.example -> Access-Control-Allow-Origin: https://evil-auditor.example, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

### 14. [LOW] CORS: subdomain origin origin accepted with credentials (`CORS1`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.aliexpress.com -> Access-Control-Allow-Origin: https://sub.aliexpress.com, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

### 15. [INFO] phpMyAdmin endpoint reachable (`P6`)

- **CWE:** CWE-200
- **Detail:** /phpmyadmin/index.php returns 200 with phpMyAdmin content.
- **Recommendation:** Restrict phpMyAdmin to management networks or add authentication.

### 16. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 17. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 18. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 19. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (59sh3v9ilyg7cc.aliexpress.com and g3nn8tf0svn97r.aliexpress.com) both resolve to distinct addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 20. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: apple-domain-verification=qipEZ2Q9JVgKJxvS-0G3nvAh729OMkjaAouGkcSxVBE; mailru-verification: c9feb214b705f911; google-site-verification=qEklE0sH9vZShePC5G6cOdQOThPhxwacj-wZuXXuMVw
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 21. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of aliexpress.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 22. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 69 disallow path(s), e.g. */aeglodetailweb/api/msite/item?productId*, /items/*, /bin/*, /search/*, /productdetail/*
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "aliexpress.com",
  "dns": {
    "a": [
      "47.246.111.53",
      "47.246.75.137"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx2.mail.aliyun.com (pref 10)"
    ],
    "ns": [
      "ns1.alibabadns.com.",
      "ns2.alibabadns.com."
    ],
    "spf": [
      "apple-domain-verification=qipEZ2Q9JVgKJxvS-0G3nvAh729OMkjaAouGkcSxVBE",
      "v=BIMI1;l=https://bimi.entrust.net/aliexpress.com/logo.svg;a=https://bimi.entrust.net/aliexpress.com/certchain.pem",
      "mailru-verification: c9feb214b705f911",
      "8rlnys07lnz6xvr7wsr4zg0kkz8yd6d5",
      "google-site-verification=qEklE0sH9vZShePC5G6cOdQOThPhxwacj-wZuXXuMVw",
      "_globalsign-domain-verification=yhVu_dlmWJNswki9B4Za7HtMd7ihnDDIzpm-RM7nMR",
      "cloudflare-verify.aliexpress.com=366647249-1105276800",
      "f6t8k5j81d8psl001ddncwt7zd1v0rr4",
      "v=spf1 include:spf1.service.alibaba.com include:spf2.service.alibaba.com include:spf2.ocm.aliyun.com -all",
      "Validity-Domain-Verification=yidvO17A1k5rojYMFX81UL2y7Cw=",
      "tnz9gvzzksy8l6y5jcmz0slnjk3yxbgm",
      "google-site-verification=GCJUnSbd3EWW3g7cRvHi57DLpGuR6CEJHzkk6-SOjAs"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-ap@service.alibaba.com; ruf=mailto:dmarc-ap@service.alibaba.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "subject": "countryName=CN, stateOrProvinceName=ZheJiang, localityName=HangZhou, organizationName=Alibaba (China) Technology Co., Ltd., commonName=*.aliexpress.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign GCC R3 OV TLS CA 2024",
    "notBefore": "May 18 11:22:02 2026 GMT",
    "notAfter": "Dec  3 11:16:15 2026 GMT",
    "san": [
      "*.aliexpress.com",
      "*.acs.aliexpress.com",
      "*.acs.aliexpress.ru",
      "*.ae.alibaba.com",
      "*.ae.aliexpress.com",
      "*.aecategoryadmin.aliexpress.com",
      "*.aliexpress-media.com",
      "*.aliexpress-tech-open.com",
      "*.aliexpress.ge",
      "*.aliexpress.ru",
      "*.aliexpress.us",
      "*.alimebot.aliexpress.com",
      "*.allinone.aliexpress.com",
      "*.ar.aliexpress.com",
      "*.ascp.aliexpress.com",
      "*.ascp.aliexpress.ru",
      "*.bops.aliexpress.ru",
      "*.br-learning.aliexpress.com",
      "*.br.aliexpress.com",
      "*.cainiao.aliexpress.com",
      "*.cdn.aliexpress-media.com",
      "*.chuangyi.aliexpress.com",
      "*.click.aliexpress.com",
      "*.click.aliexpress.ru",
      "*.click.aliexpress.us",
      "*.cobra.aliexpress.com",
      "*.componentlibs.aliexpress.com",
      "*.connect.aliexpress.com",
      "*.crm.aliexpress.com",
      "*.csp.aliexpress.com",
      "*.datamatrix.aliexpress.com",
      "*.de.aliexpress.com",
      "*.dev.aliexpress.ru",
      "*.dispute.aliexpress.com",
      "*.dos.aliexpress.com",
      "*.es-university.aliexpress.com",
      "*.es.aliexpress.com",
      "*.finnet.aliexpress.com",
      "*.fortress.aliexpress.ru",
      "*.fr-learning.aliexpress.com",
      "*.fr.aliexpress.com",
      "*.fuwu.aliexpress.com",
      "*.gds.aliexpress.com",
      "*.gearbox.aliexpress.com",
      "*.global.aliexpress.com",
      "*.he.aliexpress.com",
      "*.id.aliexpress.com",
      "*.interactive.aliexpress.com",
      "*.it-university.aliexpress.com",
      "*.it.aliexpress.com",
      "*.ja.aliexpress.com",
      "*.ko.aliexpress.com",
      "*.m.aliexpress.com",
      "*.media.aliexpress.com",
      "*.member.aliexpress.com",
      "*.mixer-pre.aliexpress.ru",
      "*.nl.aliexpress.com",
      "*.origin.aliexpress.com",
      "*.payment.aliexpress.com",
      "*.pl.aliexpress.com",
      "*.posting.aliexpress.com",
      "*.pre-datamatrix.aliexpress.com",
      "*.pre-sycm.aliexpress.com",
      "*.prepub.aliexpress.com",
      "*.pt.aliexpress.com",
      "*.ru-university.aliexpress.com",
      "*.ru.aliexpress.com",
      "*.russia-university.aliexpress.com",
      "*.russia.aliexpress.com",
      "*.seller.aliexpress.com",
      "*.seo.aliexpress.ru",
      "*.siteadmin.aliexpress.com",
      "*.src.aliexpress-media.com",
      "*.sycm.aliexpress.com",
      "*.th.aliexpress.com",
      "*.tmall.ru",
      "*.tr-university.aliexpress.com",
      "*.tr.aliexpress.com",
      "*.trendyol-university.aliexpress.com",
      "*.trendyol.aliexpress.com",
      "*.university.aliexpress.com",
      "*.us.aliexpress.com",
      "*.vi.aliexpress.com",
      "*.wapa.aliexpress.com",
      "*.workstation.aliexpress.com",
      "aliexpress.fr",
      "aliexpress.ge",
      "aliexpress.ru",
      "aliexpress.us",
      "tmall.ru",
      "www.aliexpress.fr",
      "aliexpress.com"
    ],
    "days_left": 67,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "47.246.111.53",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html;charset=UTF-8",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Tengine/AServer-Ingress"
  ],
  "cookies": [
    {
      "domain": "aliexpress.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "https://evil-auditor.example",
      "acac": "true"
    },
    {
      "origin": "https://sub.aliexpress.com",
      "acao": "https://sub.aliexpress.com",
      "acac": "true"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://aliexpress.com/"
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
    "/.git/config": 200,
    "/.env": 301,
    "/.htaccess": 200,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 200,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "apple-domain-verification=qipEZ2Q9JVgKJxvS-0G3nvAh729OMkjaAouGkcSxVBE",
    "mailru-verification: c9feb214b705f911",
    "google-site-verification=qEklE0sH9vZShePC5G6cOdQOThPhxwacj-wZuXXuMVw",
    "_globalsign-domain-verification=yhVu_dlmWJNswki9B4Za7HtMd7ihnDDIzpm-RM7nMR",
    "Validity-Domain-Verification=yidvO17A1k5rojYMFX81UL2y7Cw="
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260518112202",
      "not_after": "20261203111615"
    }
  },
  "http2": {
    "robots_disallow": [
      "*/aeglodetailweb/api/msite/item?productId*",
      "/items/*",
      "/bin/*",
      "/search/*",
      "/productdetail/*",
      "/api/*",
      "/api*.do",
      "/apps/*",
      "/downloads/*",
      "/wishlist/*",
      "/shopcart/*",
      "/brands/*",
      "/cp/*",
      "/item-img/*",
      "/product/*"
    ]
  },
  "x12": {
    "status": 200
  },
  "elapsed_s": 15.4,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
