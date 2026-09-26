# Security Audit Report — foxnews.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://foxnews.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | foxnews.com |
| Test date | 2026-09-26 18:51 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=86400 (< 31536000).
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
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: adobe-idp-site-verification=10f6011913207e944a026129f59881b0cb1078801a8c11229c6e; postman-domain-verification=da8272c2c9fcb2ddec634c78ae9e618519672e19811f32cef729; tiktok-developers-site-verification=lSBeuScXrGuauVFWLkvyQxleQhAO10IK
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of foxnews.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but foxnews.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 7 disallow path(s), e.g. /api/article-search, /search-results/, /video-search/, /printer_friendly_story/, /printer_friendly_wires/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.75.213.15 carries PTR a23-75-213-15.deploy.static.akamaitechnologies.com. for foxnews.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "foxnews.com",
  "dns": {
    "a": [
      "23.75.213.15"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-00195501.gslb.pphosted.com (pref 10)",
      "mxb-00195501.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns01.dns.fox.",
      "ns04.foxdoua.com.",
      "ns03.dns.fox.",
      "ns04.dns.fox.",
      "ns03.foxdoua.com.",
      "ns01.foxdoua.com.",
      "ns02.foxdoua.com.",
      "ns02.dns.fox."
    ],
    "spf": [
      "v=spf1 ip4:208.84.65.98 ip4:208.86.201.96 include:spf-00195501.pphosted.com include:spf.protection.outlook.com include:amazonses.com include:mail.zendesk.com include:_spf.google.com -all",
      "MS=ms40284671",
      "bppko2051pbcn9bvdualgach7h",
      "adobe-idp-site-verification=10f6011913207e944a026129f59881b0cb1078801a8c11229c6e95615eb28070",
      "MS=ms71309079",
      "265947818-2009536",
      "postman-domain-verification=da8272c2c9fcb2ddec634c78ae9e618519672e19811f32cef729d317fa89e261",
      "_4ywk6miyhayot1r60tb3ubei8wl9mvi",
      "tiktok-developers-site-verification=lSBeuScXrGuauVFWLkvyQxleQhAO10IK",
      "google-site-verification=3LvSKyvB7eXlZQtS_7fwgd0cMKh6zBBzo-g9hhEVu7k",
      "_globalsign-domain-verification=BahbT-Pu-HaLP9bBimZ0MGe-4CPc4Z_MXqKNUajBmF",
      "qRWnq9UOByGW6DnvW8qZ4scp8GbkRYG4bsmSOyP+dzlIB+XXQtkNbpBK3qVrJ8E7YT83Bk33z5CPO1L2KlH/mA=="
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=Fox News Network, LLC, commonName=wildcard.foxnews.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Feb 24 00:00:00 2026 GMT",
    "notAfter": "Feb 24 23:59:59 2027 GMT",
    "san": [
      "wildcard.foxnews.com",
      "dev-try.nation.foxnews.com",
      "dev-video.foxbusiness.com",
      "dev-video.foxnews.com",
      "events.foxnews.com",
      "feeds.foxbusiness.com",
      "feeds.foxnews.com",
      "foxbusiness.com",
      "foxnews.com",
      "foxnewsinsider.com",
      "foxnewsinternational.com",
      "hp-cms.foxbusiness.com",
      "hp-cms.foxnews.com",
      "hp.cms.foxnews.com",
      "hp.dev-cms.foxnews.com",
      "hp.staging-cms.foxnews.com",
      "liveblog-cms.foxbusiness.com",
      "liveblog-cms.foxnews.com",
      "pre-try.nation.foxnews.com",
      "public.media.foxnews.com",
      "qa.global.fncstatic.com",
      "secure.media.foxnews.com",
      "stage-pre-try.nation.foxnews.com",
      "stage-try.nation.foxnews.com",
      "stage-video.foxbusiness.com",
      "stage-video.foxnews.com",
      "try.nation.foxnews.com",
      "ak.podcast-testing.foxnewsradio.com",
      "ak.cuts.foxnewsradio.com",
      "affiliates.radio.foxnews.com",
      "*.foxnewsradio.com",
      "*.foxnewsinternational.com",
      "*.foxnews.com",
      "*.foxbusiness.com",
      "*.fncstatic.com",
      "*.fbnstatic.com",
      "beta.video.magazine.foxnews.com",
      "beta.video.latino.foxnews.com",
      "beta.video.insider.foxnews.com",
      "beta.video.foxbusiness.com",
      "ak.premium.foxnewsradio.com",
      "beta.video.foxnews.com",
      "ak.podcast.foxnewsradio.com"
    ],
    "days_left": 151,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.75.213.15",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.foxnews.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://foxnews.com/"
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
    "adobe-idp-site-verification=10f6011913207e944a026129f59881b0cb1078801a8c11229c6e",
    "postman-domain-verification=da8272c2c9fcb2ddec634c78ae9e618519672e19811f32cef729",
    "tiktok-developers-site-verification=lSBeuScXrGuauVFWLkvyQxleQhAO10IK",
    "google-site-verification=3LvSKyvB7eXlZQtS_7fwgd0cMKh6zBBzo-g9hhEVu7k",
    "_globalsign-domain-verification=BahbT-Pu-HaLP9bBimZ0MGe-4CPc4Z_MXqKNUajBmF"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260224000000",
      "not_after": "20270224235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/api/article-search",
      "/search-results/",
      "/video-search/",
      "/printer_friendly_story/",
      "/printer_friendly_wires/",
      "/wires/",
      "/xid"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a23-75-213-15.deploy.static.akamaitechnologies.com."
    ]
  },
  "elapsed_s": 10.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
