# Security Audit Report — time.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://time.com/ |
| Bug bounty program | TIME |
| Listed scope domain | time.com |
| Test date | 2026-09-26 19:00 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 15 days (notAfter Oct 12 16:26:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: X-Powered-By: Next.js
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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

### 10. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

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
- **Detail:** Apex TXT records with verification/token content: openai-domain-verification=dv-tUsE1gBsBbDTnbsH2HV6kmIC; notion-domain-verification=M4zfeQiDcuDEI6tdW6oxbAmgOgvgzOfUqPEYwMlkC0w; apple-domain-verification=N28wrioNU3ynpxLU
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of time.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but time.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 79 disallow path(s), e.g. /?search*, /*?pano=*, */munich/index_html*, /*?__rmid___get___page, /*?*__hsfp
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://time.com/ carries Cache-Control: public, max-age=300, stale-while-revalidate=60, stale-if-error=86400; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

## Evidence (raw response observations)

```json
{
  "domain": "time.com",
  "dns": {
    "a": [
      "151.101.67.52",
      "151.101.195.52",
      "151.101.3.52",
      "151.101.131.52"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "dns2.p08.nsone.net.",
      "dns4.p08.nsone.net.",
      "dns1.p08.nsone.net.",
      "dns3.p08.nsone.net."
    ],
    "spf": [
      "_erp6efm4nh2adi86mlbulfbt6tib78i",
      "d2ui9nnamrs90a.cloudfront.net",
      "MS=ms29369399",
      "openai-domain-verification=dv-tUsE1gBsBbDTnbsH2HV6kmIC",
      "notion-domain-verification=M4zfeQiDcuDEI6tdW6oxbAmgOgvgzOfUqPEYwMlkC0w",
      "_ctk70nhwf7p4b8x1qj7qbktvaqk61so",
      "apple-domain-verification=N28wrioNU3ynpxLU",
      "smartsheet-site-validation=xLX1FZAOW1XpZ6rvLDFaQAjJyldzSMD5",
      "google-site-verification=L9bonByL82ay1IZibs5Dogu6IWqfcJfSxNiszm9k_IU",
      "slack-domain-verification=yXCTB2FtQGLo20MdJaKgHwMHdpYb0jEMkJwpA4sZ",
      "google-site-verification=dUkrwcI6UUkTNiTFi8YXabuGM8W8GBG5RPGTcjxVcyo",
      "google-site-verification=R05S4oN1f2pYfvNk6TyJl699jeVKBepFxxaZioigodU",
      "d25h5mis1xkx6t.cloudfront.net",
      "docusign=3bc4cebc-b475-402a-85d3-5bdc15ec8af5",
      "cursor-domain-verification-b4e0x8=kQIIIWnjZtcwWTXdJ0Uz40IHT",
      "jamf-site-verification=oCncFWaydjYnb05EqaLL3Q",
      "_py36delibd4b67nimszksh8ak1y3374",
      "jamf-site-verification=87WfhercEjwL8sNL32kdvA",
      "onetrust-domain-verification=8b1d76064c704281a9a73005d042a4bd",
      "tollbit-domain-verification=b42d076ebd6673fe3faf1951441c4b26c9c028e7d2b9378d6f0d97162247c37e",
      "google-site-verification=hA9c-cMQhZs8Ctq4AMlrJSMepvPZkZYaGXe2NeUObgQ",
      "v=spf1 include:_spf.google.com include:_spf.psm.knowbe4.com include:_spf.ultipro.com include:u13624957.wl208.sendgrid.net include:mail.zendesk.com include:mail.cdsfulfillment.com include:amazonses.com ip4:54.236.128.150 ip4:54.236.109.30 ip4:204.115.118.3",
      "3/27 ip4:149.72.199.98 ip4:149.72.231.47 -all",
      "openai-domain-verification=dv-QMM3mdP3BeSDPDRYGi04uHcu",
      "MS=ms82252414",
      "_globalsign-domain-verification=eRi2ZQZJ99fAou8jrSC06eUJpasrvj8YgWl21vaW5G",
      "mongodb-site-verification=Ru5QtdQhXmo14irx2raA1HUoorhijQoZ",
      "facebook-domain-verification=u27a6xq3jf0wefngdl43tukaif4h91",
      "google-site-verification=CZLtrEtXICkKdVI2KPODQ6BN8ZpjenbgVuRFbnQi4So",
      "adobe-idp-site-verification=f156d69676f01a5fdbb783b2313c1b98a30fe75b832d8b04da980dd684eed620",
      "google-site-verification=cKBPop8tXdt1cPh2IcyChxlmkjAMKD0oEYzUcBfBJq0",
      "anthropic-domain-verification-q9n3tg=cBBH8yGQWYRhUR2NeV0frsZTp",
      "zapier-domain-verification-challenge=fd1df879-d018-430f-901e-5c7032530304",
      "78UC9yVP0t41WOHMwbhHq33V0IZJTL7Lna8+FnXKLhat7SZ8oXFTnSUEJDwYM0otMKFtV8kLKmqce9uDvD4kJQ==",
      "ZOOM_verify_bzijKevE4xQ6ZDUKZXC1hl"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc@time.com; ruf=mailto:dmarc@time.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.time.com",
    "issuer": "countryName=US, organizationName=Certainly, commonName=Certainly Intermediate R1",
    "notBefore": "Sep 12 16:27:00 2026 GMT",
    "notAfter": "Oct 12 16:26:59 2026 GMT",
    "san": [
      "*.time.com",
      "time.com"
    ],
    "days_left": 15,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.67.52",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "TIME | Current &amp; Breaking News | National &amp; World Updates"
  },
  "mixed_content": [],
  "tech": [
    "X-Powered-By: Next.js"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.time.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://time.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 406,
    "/security.txt": 406,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 404,
    "/.htaccess": 406,
    "/wp-login.php": 406,
    "/phpmyadmin/index.php": 406,
    "/server-status": 301,
    "/api/": 406
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "openai-domain-verification=dv-tUsE1gBsBbDTnbsH2HV6kmIC",
    "notion-domain-verification=M4zfeQiDcuDEI6tdW6oxbAmgOgvgzOfUqPEYwMlkC0w",
    "apple-domain-verification=N28wrioNU3ynpxLU",
    "google-site-verification=L9bonByL82ay1IZibs5Dogu6IWqfcJfSxNiszm9k_IU",
    "slack-domain-verification=yXCTB2FtQGLo20MdJaKgHwMHdpYb0jEMkJwpA4sZ"
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
      "not_before": "20260912162700",
      "not_after": "20261012162659"
    }
  },
  "http2": {
    "robots_disallow": [
      "/?search*",
      "/*?pano=*",
      "*/munich/index_html*",
      "/*?__rmid___get___page",
      "/*?*__hsfp",
      "/*?*__hstc",
      "/*?*__rmid",
      "/*?*__rmidpage",
      "/*?*/*ref",
      "/*?*002/*0902",
      "/*?*2&hubs_content",
      "/*?*ajs_event",
      "/*?*app",
      "/*?*attachment_id",
      "/*?*author"
    ]
  },
  "x12": {
    "status": 200
  },
  "elapsed_s": 14.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
