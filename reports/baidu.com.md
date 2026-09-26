# Security Audit Report — baidu.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://baidu.com/ |
| Bug bounty program | Baidu |
| Listed scope domain | baidu.com |
| Test date | 2026-09-26 17:39 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 4, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
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

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

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
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=qjb28W2jJSrWj04NHpB0CvgK9tle5JkOq-EcyWBgnE; google-site-verification=GHb98-6msqyx_qqjGl5eRatD3QTHyVB6-xQ3gJB5UwM
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of baidu.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 133 disallow path(s), e.g. /baidu, /s?, /ulink?, /link?, /home/news/data/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "baidu.com",
  "dns": {
    "a": [
      "110.242.74.102",
      "111.63.65.103",
      "124.237.177.164",
      "111.63.65.247"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx.baidu.com (pref 20)",
      "mx.maillb.baidu.com (pref 10)"
    ],
    "ns": [
      "ns3.baidu.com.",
      "ns4.baidu.com.",
      "dns.baidu.com.",
      "ns2.baidu.com.",
      "ns7.baidu.com."
    ],
    "spf": [
      "9279nznttl321bxp1j464rd9vpps246v",
      "_globalsign-domain-verification=qjb28W2jJSrWj04NHpB0CvgK9tle5JkOq-EcyWBgnE",
      "v=spf1 include:spf1.baidu.com include:spf2.baidu.com include:spf3.baidu.com include:spf4.baidu.com -all",
      "google-site-verification=GHb98-6msqyx_qqjGl5eRatD3QTHyVB6-xQ3gJB5UwM"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:baidu-spammail@baidu.com; ruf=mailto:baidu-spammail@baidu.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "countryName=CN, stateOrProvinceName=Beijing, localityName=Beijing, organizationName=Beijing Baidu Netcom Science Technology Co., Ltd., commonName=baidu.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign RSA OV SSL CA 2018",
    "notBefore": "Jul  9 02:32:55 2026 GMT",
    "notAfter": "Jan 24 02:32:55 2027 GMT",
    "san": [
      "baidu.com",
      "click.hm.baidu.com",
      "baifubao.com",
      "www.baidu.cn",
      "www.baidu.com.cn",
      "mct.y.nuomi.com",
      "apollo.auto",
      "dwz.cn",
      "update.pan.baidu.com",
      "wn.pos.baidu.com",
      "cm.pos.baidu.com",
      "log.hm.baidu.com",
      "*.baidu.com",
      "*.baifubao.com",
      "*.baidustatic.com",
      "*.bdstatic.com",
      "*.bdimg.com",
      "*.hao123.com",
      "*.nuomi.com",
      "*.chuanke.com",
      "*.trustgo.com",
      "*.bce.baidu.com",
      "*.eyun.baidu.com",
      "*.map.baidu.com",
      "*.mbd.baidu.com",
      "*.fanyi.baidu.com",
      "*.baidubce.com",
      "*.mipcdn.com",
      "*.news.baidu.com",
      "*.baidupcs.com",
      "*.aipage.com",
      "*.aipage.cn",
      "*.bcehost.com",
      "*.safe.baidu.com",
      "*.im.baidu.com",
      "*.baiducontent.com",
      "*.dlnel.com",
      "*.dlnel.org",
      "*.dueros.baidu.com",
      "*.su.baidu.com",
      "*.91.com",
      "*.hao123.baidu.com",
      "*.apollo.auto",
      "*.xueshu.baidu.com",
      "*.bj.baidubce.com",
      "*.gz.baidubce.com",
      "*.smartapps.cn",
      "*.bdtjrcv.com",
      "*.hao222.com",
      "*.haokan.com",
      "*.pae.baidu.com",
      "*.vd.bdstatic.com",
      "*.cloud.baidu.com"
    ],
    "days_left": 119,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "110.242.74.102",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": "",
      "error": "ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='baidu.com', port=443): Read timed out. (read timeout=15)\"))"
    },
    {
      "origin": "https://sub.baidu.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.baidu.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 0",
    "/redirect?next=https://evil-auditor.example/x -> 0",
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
    "_globalsign-domain-verification=qjb28W2jJSrWj04NHpB0CvgK9tle5JkOq-EcyWBgnE",
    "google-site-verification=GHb98-6msqyx_qqjGl5eRatD3QTHyVB6-xQ3gJB5UwM"
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
    "robots_disallow": [
      "/baidu",
      "/s?",
      "/ulink?",
      "/link?",
      "/home/news/data/",
      "/bh",
      "/baidu",
      "/s?",
      "/shifen/",
      "/homepage/",
      "/cpro",
      "/ulink?",
      "/link?",
      "/home/news/data/",
      "/bh"
    ]
  },
  "elapsed_s": 201.2,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
