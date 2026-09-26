# Security Audit Report — yadi.sk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yadi.sk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | yadi.sk |
| Test date | 2026-09-26 23:41 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 4, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 8 | low | CK4 | Session-like cookie without HttpOnly | CWE-1004 |
| 9 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 10 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 11 | low | RD2 | HTTPS root redirects to a different domain | CWE-200 |
| 12 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 13 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 14 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 15 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 16 | info | CT1 | 2 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=ZIE7lnBAHKRRAGoG_hFijsNTqp_so1pEzNwsMUA4xI
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 8. [LOW] Session-like cookie without HttpOnly (`CK4`)

- **CWE:** CWE-1004
- **Detail:** Cookie 'yandex_360_session_exp_cache' looks session-related and has no HttpOnly attribute.
- **Recommendation:** Set HttpOnly on session cookies.

### 9. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 27 disallow path(s), e.g. /pay/, /activation_failed, /cfg, /folder, /copy
- **Recommendation:** Review disallowed paths; robots is not access control.

### 10. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 87.250.250.50 carries PTR disk-front.stable.qloud-b.yandex.net. for yadi.sk.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 11. [LOW] HTTPS root redirects to a different domain (`RD2`)

- **CWE:** CWE-200
- **Detail:** https://yadi.sk/ answered 302 with Location: https://disk.yandex.com (cross-domain handoff at the entry point).
- **Recommendation:** Review the cross-domain redirect; it discloses the real entry point and can be abused in open-redirect-style flows.

### 12. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on yadi.sk; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 13. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for yadi.sk, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 14. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The yadi.sk certificate lists an AIA OCSP responder (http://ocsp.globalsign.com/gsgccr46ovtlsca2025) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 15. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on yadi.sk is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 16. [INFO] 2 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "yadi.sk",
  "dns": {
    "a": [
      "87.250.250.50"
    ],
    "aaaa": [
      "2a02:6b8::2:50"
    ],
    "cname": null,
    "mx": [],
    "ns": [
      "ns4.yandex.ru.",
      "ns3.yandex.ru."
    ],
    "caa": [],
    "spf": [
      "45e3b7565dc5130458f2bead528f8f6000d78f2b5fd904b06355c19f0cd3e4f",
      "_globalsign-domain-verification=ZIE7lnBAHKRRAGoG_hFijsNTqp_so1pEzNwsMUA4xI",
      "96ecd6928cf6313019cf2d11dc11d6fa945e5d808fcd391ce076bcd6968aa39"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=RU, stateOrProvinceName=Moscow, localityName=Moscow, organizationName=YANDEX LLC, commonName=disk.yandex.ru",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign GCC R46 OV TLS CA 2025",
    "notBefore": "Sep  1 15:16:16 2026 GMT",
    "notAfter": "Mar  1 20:59:59 2027 GMT",
    "san": [
      "disk.yandex.ru",
      "docs.360.yandex.tm",
      "docs.360.yandex.tj",
      "docs.360.yandex.md",
      "docs.360.yandex.lv",
      "docs.360.yandex.lt",
      "docs.360.yandex.kg",
      "docs.360.yandex.fr",
      "docs.360.yandex.ee",
      "docs.360.yandex.com.tr",
      "docs.360.yandex.com.ge",
      "docs.360.yandex.com.am",
      "docs.360.yandex.com",
      "docs.360.yandex.co.il",
      "docs.360.yandex.az",
      "docs.yandex.tm",
      "docs.yandex.tj",
      "docs.yandex.md",
      "docs.yandex.lv",
      "docs.yandex.lt",
      "docs.yandex.kg",
      "docs.yandex.fr",
      "docs.yandex.ee",
      "docs.yandex.com.tr",
      "docs.yandex.com.ge",
      "docs.yandex.com.am",
      "docs.yandex.com",
      "docs.yandex.co.il",
      "docs.yandex.az",
      "disk.yandex.kz",
      "disk.yandex.com",
      "disk.yandex.uz",
      "disk.yandex.kg",
      "yadi.sk",
      "disk.yandex.net",
      "disk.yandex.by",
      "disk.yandex.com.ge",
      "disk.yandex.tm",
      "disk.yandex.tj",
      "disk.yandex.lv",
      "disk.yandex.ee",
      "disk.yandex.lt",
      "docs.yandex.ru",
      "disk.yandex.com.tr",
      "disk.yandex.com.am",
      "disk.yandex.fr",
      "disk.yandex.co.il",
      "disk.yandex.az",
      "disk.yandex.md",
      "docs.yandex.by",
      "docs.yandex.kz",
      "disk.360.yandex.ru",
      "disk.360.yandex.az",
      "disk.360.yandex.by",
      "disk.360.yandex.co.il",
      "disk.360.yandex.com",
      "disk.360.yandex.com.am",
      "disk.360.yandex.com.ge",
      "disk.360.yandex.com.tr",
      "disk.360.yandex.ee",
      "disk.360.yandex.fr",
      "disk.360.yandex.kg",
      "disk.360.yandex.kz",
      "disk.360.yandex.lt",
      "disk.360.yandex.lv",
      "disk.360.yandex.md",
      "disk.360.yandex.net",
      "disk.360.yandex.tj",
      "disk.360.yandex.tm",
      "disk.360.yandex.uz",
      "docs.360.yandex.ru",
      "docs.360.yandex.by",
      "docs.360.yandex.kz",
      "docs.yandex.uz",
      "docs.360.yandex.uz"
    ],
    "days_left": 155,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "87.250.250.50",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [
    {},
    {
      "domain": ".yadi.sk",
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
      "origin": "https://sub.yadi.sk",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://yadi.sk/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 200,
    "/.git/config": 200,
    "/.env": 200,
    "/.htaccess": 200,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 200,
    "/server-status": 200,
    "/api/": 200
  },
  "subdomains": {
    "source": "certspotter",
    "count": 2,
    "notable": [],
    "sample": [
      "www.yadi.sk",
      "yadi.sk"
    ]
  },
  "apex_txt": [
    "_globalsign-domain-verification=ZIE7lnBAHKRRAGoG_hFijsNTqp_so1pEzNwsMUA4xI"
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
      "aia_ocsp": "http://ocsp.globalsign.com/gsgccr46ovtlsca2025",
      "serial": 4345114257691600411259394893,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.globalsign.com/gsgccr46ovtlsca2025.crl"
      ],
      "subject_dn": "310b3009060355040613025255310f300d060355040813064d6f73636f77310f300d060355040713064d6f73636f7731133011060355040a130a59414e444558204c4c43311730150603550403130e6469736b2e79616e6465782e7275",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312a302806035504031321476c6f62616c5369676e2047434320523436204f5620544c532043412032303235",
      "not_before": "20260901151616",
      "not_after": "20270301205959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/pay/",
      "/activation_failed",
      "/cfg",
      "/folder",
      "/copy",
      "/download/Yandex.Disk.Mac.dmg",
      "/download/YandexDiskSetup.exe",
      "/download/YandexDiskSetupPack.exe",
      "/client/",
      "/models/",
      "/tuning/",
      "/gift",
      "/payment/",
      "/ping",
      "/monitoring.txt"
    ]
  },
  "x12": {
    "status": 302,
    "ptr": [
      "disk-front.stable.qloud-b.yandex.net."
    ]
  },
  "x13": {
    "root_status": 302,
    "root_location": "https://disk.yandex.com",
    "http_status": 301,
    "p404_status": 200,
    "wellknown": [
      "/.well-known/assetlinks.json"
    ],
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 302,
    "security_txt": "/.well-known/security.txt",
    "crl": {
      "url": "http://crl.globalsign.com/gsgccr46ovtlsca2025.crl",
      "status": 200
    }
  },
  "elapsed_s": 47.9,
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
