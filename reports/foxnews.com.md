# Security Audit Report — foxnews.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://foxnews.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | foxnews.com |
| Test date | 2026-09-27 00:19 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 4, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 9 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=300 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 9. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.foxnews.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: postman-domain-verification=da8272c2c9fcb2ddec634c78ae9e618519672e19811f32cef729; tiktok-developers-site-verification=lSBeuScXrGuauVFWLkvyQxleQhAO10IK; google-site-verification=3LvSKyvB7eXlZQtS_7fwgd0cMKh6zBBzo-g9hhEVu7k
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.digicert.com -> http-200
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but foxnews.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 7 disallow path(s), e.g. /api/article-search, /search-results/, /video-search/, /printer_friendly_story/, /printer_friendly_wires/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.15.141.128 carries PTR a23-15-141-128.deploy.static.akamaitechnologies.com. for foxnews.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for foxnews.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on foxnews.com lists 316 <loc> URL(s) across 317 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

## Evidence (raw response observations)

```json
{
  "domain": "foxnews.com",
  "dns": {
    "a": [
      "23.15.141.128"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-00195501.gslb.pphosted.com (pref 10)",
      "mxa-00195501.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns02.dns.fox.",
      "ns02.foxdoua.com.",
      "ns01.foxdoua.com.",
      "ns04.foxdoua.com.",
      "ns03.dns.fox.",
      "ns03.foxdoua.com.",
      "ns04.dns.fox.",
      "ns01.dns.fox."
    ],
    "caa": [],
    "spf": [
      "postman-domain-verification=da8272c2c9fcb2ddec634c78ae9e618519672e19811f32cef729d317fa89e261",
      "tiktok-developers-site-verification=lSBeuScXrGuauVFWLkvyQxleQhAO10IK",
      "google-site-verification=3LvSKyvB7eXlZQtS_7fwgd0cMKh6zBBzo-g9hhEVu7k",
      "MS=ms71309079",
      "_4ywk6miyhayot1r60tb3ubei8wl9mvi",
      "qRWnq9UOByGW6DnvW8qZ4scp8GbkRYG4bsmSOyP+dzlIB+XXQtkNbpBK3qVrJ8E7YT83Bk33z5CPO1L2KlH/mA==",
      "bppko2051pbcn9bvdualgach7h",
      "adobe-idp-site-verification=10f6011913207e944a026129f59881b0cb1078801a8c11229c6e95615eb28070",
      "v=spf1 ip4:208.84.65.98 ip4:208.86.201.96 include:spf-00195501.pphosted.com include:spf.protection.outlook.com include:amazonses.com include:mail.zendesk.com include:_spf.google.com -all",
      "_globalsign-domain-verification=BahbT-Pu-HaLP9bBimZ0MGe-4CPc4Z_MXqKNUajBmF",
      "265947818-2009536",
      "MS=ms40284671"
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
    "days_left": 150,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.15.141.128",
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
      "acao": "*",
      "acac": "false"
    },
    {
      "origin": "https://sub.foxnews.com",
      "acao": "*",
      "acac": "false"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.foxnews.com/"
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
    "postman-domain-verification=da8272c2c9fcb2ddec634c78ae9e618519672e19811f32cef729",
    "tiktok-developers-site-verification=lSBeuScXrGuauVFWLkvyQxleQhAO10IK",
    "google-site-verification=3LvSKyvB7eXlZQtS_7fwgd0cMKh6zBBzo-g9hhEVu7k",
    "adobe-idp-site-verification=10f6011913207e944a026129f59881b0cb1078801a8c11229c6e",
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
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 7849936068577023711495358862610657137,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
        "http://crl4.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl"
      ],
      "subject_dn": "310b30090603550406130255533111300f060355040813084e657720596f726b3111300f060355040713084e657720596f726b311e301c060355040a1315466f78204e657773204e6574776f726b2c204c4c43311d301b0603550403131477696c64636172642e666f786e6577732e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473320544c532045434320534841333834203230323020434131",
      "not_before": "20260224000000",
      "not_after": "20270224235959"
    },
    "ocsp": "http-200"
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
      "a23-15-141-128.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.foxnews.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=300",
    "sitemap": {
      "urls": 316,
      "indexes": 317
    },
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "elapsed_s": 25.6,
  "rechecked": "2026-09-27 00:08 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- re-run #15 passive additions: TLS 1.0/1.1, cipher-suite and key-exchange observations come from the handshake the base TLS check already performed plus one quiet re-handshake with no HTTP traffic; HTML-level angles read the root document already fetched for header checks; the only extra request this pass is a read-only GET to /.well-known/openid-configuration (plus the earlier passes' security.txt, sitemap.xml and CRL GETs).
- Findings are reported against the public program scope; submission through the program tracker is pending.
