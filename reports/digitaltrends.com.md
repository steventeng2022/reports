# Security Audit Report — digitaltrends.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://digitaltrends.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | digitaltrends.com |
| Test date | 2026-09-27 00:15 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 4, Info: 20)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 13 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 19 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 20 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 21 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 22 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 23 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 24 | info | CT1 | 23 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 13. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.digitaltrends.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

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
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=fJAmOfQYHw3K7C1fuKa4yAi1JiFeMy47sg81/YoPzdpRty8zLV; facebook-domain-verification=o9gokha6nwug1sltr4wj9wtcks2ro4; tollbit-domain-verification=834a1886734f6bddd5015deaacc39c6e682c78b4e60db097b72d
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 19. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 103 disallow path(s), e.g. /, /page/, /tag/, /author/, /feed/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 20. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.169.55.55 carries PTR server-3-169-55-55.tpe54.r.cloudfront.net. for digitaltrends.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 21. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for digitaltrends.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 22. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of digitaltrends.com loads 2 cross-origin script(s) without an integrity attribute, e.g. https://fde470f3808d.1bca2ace.ap-northeast-1.token.awswaf.com/fde470f3808d/855206840c82/8ec0fee2edbb/challenge.js, https://fde470f3808d.1bca2ace.ap-northeast-1.captcha.awswaf.com/fde470f3808d/855206840c82/8ec0fee2edbb/captcha.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 23. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on digitaltrends.com lists 294 <loc> URL(s) across 295 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 24. [INFO] 23 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: altis.staging.es.digitaltrends.com, altis.staging.www.digitaltrends.com, dev.es.digitaltrends.com, dev.www.digitaltrends.com, files.digitaltrends.com, staging.altis.digitaltrends.com, staging.es.digitaltrends.com, staging.www.digitaltrends.com, status.digitaltrends.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "digitaltrends.com",
  "dns": {
    "a": [
      "3.169.55.55",
      "3.169.55.28",
      "3.169.55.39",
      "3.169.55.89"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "digitaltrends-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns-78.awsdns-09.com.",
      "ns-666.awsdns-19.net.",
      "ns-1522.awsdns-62.org.",
      "ns-1711.awsdns-21.co.uk."
    ],
    "caa": [],
    "spf": [
      "atlassian-domain-verification=fJAmOfQYHw3K7C1fuKa4yAi1JiFeMy47sg81/YoPzdpRty8zLVRGO0RsFE2nBJ8M",
      "facebook-domain-verification=o9gokha6nwug1sltr4wj9wtcks2ro4",
      "0ed1fe018a398da5ca17fb44baa314e68a3dc33e5d",
      "MS=ms61723988",
      "tollbit-domain-verification=834a1886734f6bddd5015deaacc39c6e682c78b4e60db097b72da9aa949d693d",
      "google-site-verification=LhEEOYALF-FSwQtsNYjY34HKhnDVrnDjf79R-jywnA8",
      "5HwOFRfvC6HJXoxZ0NSTFWTYRqxdotArg8062xyCJLY=",
      "ahrefs-site-verification_9a82eef87599150f2c7cb0a33fd6674efaec660b67d411fe3aaed0db8e928d0d",
      "google-site-verification=-MksWPwuf34sS1-oJvSzJIW9KsE7CskTBNvUJUs9zGU",
      "fastly-domain-delegation-kjfbsakjhkjfakl-178404-2019-10-16",
      "dropbox-domain-verification=9zrbo1ot31id",
      "google-site-verification=KwP_ps6K2dA_GqqH09sP6ZRPv71JHxnSBwoZ9uSyCgo",
      "_globalsign-domain-verification=Fw09cFhmPL_-Bfg6BV5_NkyDEkXJfmQd4uPViX560A",
      "atlassian-domain-verification=3UciTRhiPPalGnfMwEyifXMToIaV1gtpnmaMiUMu/9js/FnaCipcVQtCjIbTpoMk",
      "google-gws-recovery-domain-verification=71417947",
      "MS=ms32022712",
      "anthropic-domain-verification-126xck=x61kgVFV21lGsbJaZccxJJXDS",
      "v=spf1 include:spf.protection.outlook.com include:spf.tipalti.com -all",
      "google-site-verification=nZ03eoxIbZX2vx96rqCcdtoGnh3s5YYKrTLrXSNsrBk",
      "uber-domain-verification=69ff25a9-2786-43e3-a501-el0bf2fcf5c6",
      "ZOOM_verify_XXjQmpVqSESiHkuoW4HdGw",
      "google-site-verification=DGgmOFBDVC5ksJtU4Q5hyh9CvOXOdkNApwFou-IFOVo",
      "yandex-verification: d3d90a55ca899aa7",
      "apple-domain-verification=ixKwVGxwE9TXeZ3F",
      "google-site-verification=9UqhZ3_NAJ9h080POi3QF5x58xVh8Fh6ksz_7VTBhrA",
      "openai-domain-verification=dv-YGTwSC2FWeOKciA5bJnao9yN"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:newsletter@digitaltrends.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=digitaltrends-prod.altis.cloud",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Nov 29 00:00:00 2025 GMT",
    "notAfter": "Dec 28 23:59:59 2026 GMT",
    "san": [
      "digitaltrends-prod.altis.cloud",
      "altis.www.21oak.com",
      "altis.www.happysprout.com",
      "www.pawtracks.com",
      "21oak.com",
      "altis.es.digitaltrends.com",
      "altis.www.digitaltrends.com",
      "themanual.com",
      "altis.www.toughjobs.com",
      "digitaltrends.com",
      "pawtracks.com",
      "happysprout.com",
      "www.toughjobs.com",
      "www.blissmark.com",
      "altis.www.themanual.com",
      "blissmark.com",
      "altis.www.pawtracks.com",
      "*.digitaltrends-prod.altis.cloud",
      "toughjobs.com",
      "www.digitaltrends.com",
      "newfolks.com",
      "es.digitaltrends.com",
      "altis.www.blissmark.com",
      "www.themanual.com",
      "www.happysprout.com",
      "altis.www.newfolks.com",
      "www.newfolks.com",
      "www.21oak.com"
    ],
    "days_left": 92,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.55.55",
    "open": []
  },
  "https": {
    "status": 405,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.digitaltrends.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://digitaltrends.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 405",
    "/redirect?next=https://evil-auditor.example/x -> 405",
    "/go?url=https://evil-auditor.example/x -> 405",
    "/url?url=https://evil-auditor.example/x -> 405"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 405,
    "/.git/config": 405,
    "/.env": 403,
    "/.htaccess": 405,
    "/wp-login.php": 405,
    "/phpmyadmin/index.php": 405,
    "/server-status": 405,
    "/api/": 405
  },
  "subdomains": {
    "source": "certspotter",
    "count": 23,
    "notable": [
      "altis.staging.es.digitaltrends.com",
      "altis.staging.www.digitaltrends.com",
      "dev.es.digitaltrends.com",
      "dev.www.digitaltrends.com",
      "files.digitaltrends.com",
      "staging.altis.digitaltrends.com",
      "staging.es.digitaltrends.com",
      "staging.www.digitaltrends.com",
      "status.digitaltrends.com"
    ],
    "sample": [
      "altis.es.digitaltrends.com",
      "altis.staging.es.digitaltrends.com",
      "altis.staging.www.digitaltrends.com",
      "altis.www.digitaltrends.com",
      "click.digitaltrends.com",
      "dev.es.digitaltrends.com",
      "dev.www.digitaltrends.com",
      "digitaltrends.com",
      "elinkeb3.digitaltrends.com",
      "es.digitaltrends.com",
      "explore.digitaltrends.com",
      "files.digitaltrends.com",
      "guide.digitaltrends.com",
      "phluant.digitaltrends.com",
      "results.digitaltrends.com",
      "rs-stripe.digitaltrends.com",
      "sli.digitaltrends.com",
      "staging.altis.digitaltrends.com",
      "staging.es.digitaltrends.com",
      "staging.www.digitaltrends.com"
    ]
  },
  "apex_txt": [
    "atlassian-domain-verification=fJAmOfQYHw3K7C1fuKa4yAi1JiFeMy47sg81/YoPzdpRty8zLV",
    "facebook-domain-verification=o9gokha6nwug1sltr4wj9wtcks2ro4",
    "tollbit-domain-verification=834a1886734f6bddd5015deaacc39c6e682c78b4e60db097b72d",
    "google-site-verification=LhEEOYALF-FSwQtsNYjY34HKhnDVrnDjf79R-jywnA8",
    "ahrefs-site-verification_9a82eef87599150f2c7cb0a33fd6674efaec660b67d411fe3aaed0d"
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
      "aia_ocsp": "http://ocsp.r2m04.amazontrust.com",
      "serial": 19213268236565719644188287649096152059,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "subject_dn": "312730250603550403131e6469676974616c7472656e64732d70726f642e616c7469732e636c6f7564",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20251129000000",
      "not_after": "20261228235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/page/",
      "/tag/",
      "/author/",
      "/feed/",
      "/trash/",
      "/uncategorized/",
      "/?*",
      "/feed/",
      "/?feed=rss2",
      "/wp-admin/",
      "/wp-login.php",
      "/*?rand=",
      "/*?s=",
      "/search"
    ]
  },
  "x12": {
    "status": 405,
    "ptr": [
      "server-3-169-55-55.tpe54.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 405,
    "http_status": 301,
    "p404_status": 405,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 405,
    "sitemap": {
      "urls": 294,
      "indexes": 295
    },
    "crl": {
      "url": "http://crl.r2m04.amazontrust.com/r2m04.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 405
  },
  "elapsed_s": 11.4,
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
