# Security Audit Report — justgiving.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://justgiving.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | justgiving.com |
| Test date | 2026-09-27 00:24 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 1, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | MAIL10 | DMARC subdomain policy (sp=) set while apex policy is p=none | CWE-285 |
| 9 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 10 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 11 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 12 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 17 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 18 | info | HTML3 | Third-party <iframe> embedded in root document | CWE-643 |
| 19 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 20 | info | CT1 | 38 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AmazonS3
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AmazonS3
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] DMARC subdomain policy (sp=) set while apex policy is p=none (`MAIL10`)

- **CWE:** CWE-285
- **Detail:** Subdomains are enforced while the apex domain is monitor-only.
- **Recommendation:** Confirm the split policy is intended.

### 9. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 10. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 11. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=9Ie7V9M2YudzHmywa873FdLnRJKZY57zwKHzQLgj_Kw; miro-verification=0a2e1dbb2412c140c5fd914272eb7e9480bf1d6e; google-site-verification=2l0z9VQCacbAFBgCmfbC47bnTeHQcq4LWOHoIzYG72Q
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 12. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m01.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 37 disallow path(s), e.g. /, /, /user-account/, /charity/search, /fundraiser/search
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://justgiving.com/ carries Cache-Control: public, max-age=60 (plus ETag/Last-Modified freshness fields); shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.169.55.71 carries PTR server-3-169-55-71.tpe54.r.cloudfront.net. for justgiving.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkcgbw65n69ldx.html -> 404; error page/headers match: CloudFront.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 17. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of justgiving.com loads 1 cross-origin script(s) without an integrity attribute, e.g. https://www.jg-cdn.com/assets/jg-homepage/config/config.661d9a9ddc21.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 18. [INFO] Third-party <iframe> embedded in root document (`HTML3`)

- **CWE:** CWE-643
- **Detail:** Root document of justgiving.com embeds 1 cross-origin iframe(s), e.g. https://www.googletagmanager.com/ns.html?id=GTM-WL6ZNN; embedded origins are framed inside the page with its trust context.
- **Recommendation:** Review embedded origins and consider sandbox attributes.

### 19. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on justgiving.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 20. [INFO] 38 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: app.justgiving.com, blog.justgiving.com, csp-report.staging.justgiving.com, fitness.staging.justgiving.com, graphql.staging.justgiving.com, help.justgiving.com, id.staging.justgiving.com, internal.staging.justgiving.com, media.justgiving.com, pagesettings.staging.justgiving.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "justgiving.com",
  "dns": {
    "a": [
      "3.169.55.71",
      "3.169.55.28",
      "3.169.55.52",
      "3.169.55.116"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx2.blackbaud.iphmx.com (pref 5)",
      "mx1.blackbaud.iphmx.com (pref 1)"
    ],
    "ns": [
      "ns-1865.awsdns-41.co.uk.",
      "ns-959.awsdns-55.net.",
      "ns-493.awsdns-61.com.",
      "ns-1506.awsdns-60.org."
    ],
    "caa": [
      "0 issue \"amazonaws.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"digicert.com\"",
      "0 iodef \"mailto:security@justgiving.com\""
    ],
    "spf": [
      "CKO=cli_r5yskqycwsle3mrla2l4xig4pa",
      "google-site-verification=9Ie7V9M2YudzHmywa873FdLnRJKZY57zwKHzQLgj_Kw",
      "mixpanel-domain-verify=5386caff-2971-4e94-aee0-4d3b5ab42b90",
      "00D200000000iaP=1TBN2000000015l",
      "miro-verification=0a2e1dbb2412c140c5fd914272eb7e9480bf1d6e",
      "CKO=cli_nsgsiliz6ygezevfc2osdkvtju",
      "MS=ms21109735",
      "google-site-verification=2l0z9VQCacbAFBgCmfbC47bnTeHQcq4LWOHoIzYG72Q",
      "v=spf1 mx a include:cust-spf.exacttarget.com include:mktomail.com include:spf.protection.outlook.com include:mail.zendesk.com include:spf.mandrillapp.com -all",
      "_ziryvqp598rhu877n5y4wj0shxxojdp",
      "docker-verification=eb8aed88-9460-4fab-9ef2-5ce59854ecc7",
      "lucid-verification=fcj@cjz6eat.zgj9WMQ",
      "atlassian-domain-verification=S8uXCQd2FYeOlTqNnRo41gCwYfu8sO1gASeWx63dP5j6Yh0iNdqHotTlne8l2f50",
      "MS=ms82130383",
      "google-site-verification=a4kUdVdhuRGENeMFXISY5ile-NsMNYxcyAsHknjaeSs",
      "anthropic-domain-verification-bkk0a0=vsXwOsqFiYmbQeQS4m4KiVc0Y",
      "smartsheet-site-validation=-ukamuNj8Xn3s0SyCGx2Xe5Vt2oDQ46I",
      "stripe-verification=3c386b3bd938d27ee26d142e2d3201f0d49dfd68edc01090aeb71a5d542819aa",
      "MS=ms63724168",
      "MS=ms30587875",
      "0TPSldHHJ3AnIIANqD3HTiUcd/40SZ097zvG7L1hCQsTA5IkkNpnVNZhBPjaoZJjwCPHtr8iDe8kdsvHGi9xSA==",
      "figma-domain-verification=8a13494f101d6ca661f43b722f9d090d5a2a2ac65283628d50cfea15ce7e3076-1723691631",
      "adobe-sign-verification=e1e4662cb4cb8921b04ff65aacba0578"
    ],
    "dmarc": [
      "v=DMARC1; p=none; pct=100; rua=mailto:re+gbzuz3j7wtb@dmarc.postmarkapp.com,mailto:re+or5o1vetcy9@dmarc.postmarkapp.com; sp=none; aspf=r;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.justgiving.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Nov  3 00:00:00 2025 GMT",
    "notAfter": "Dec  1 23:59:59 2026 GMT",
    "san": [
      "*.justgiving.com",
      "justgiving.com"
    ],
    "days_left": 65,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.55.71",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Online fundraising donations and ideas - JustGiving"
  },
  "mixed_content": [],
  "tech": [
    "Server: AmazonS3"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.justgiving.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://justgiving.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "source": "certspotter",
    "count": 38,
    "notable": [
      "app.justgiving.com",
      "blog.justgiving.com",
      "csp-report.staging.justgiving.com",
      "fitness.staging.justgiving.com",
      "graphql.staging.justgiving.com",
      "help.justgiving.com",
      "id.staging.justgiving.com",
      "internal.staging.justgiving.com",
      "media.justgiving.com",
      "pagesettings.staging.justgiving.com",
      "receipts.staging.justgiving.com",
      "staging.justgiving.com",
      "static.justgiving.com",
      "static.staging.justgiving.com",
      "tags-fitness.staging.justgiving.com"
    ],
    "sample": [
      "app.justgiving.com",
      "bbid.justgiving.com",
      "blog.justgiving.com",
      "click.contact.justgiving.com",
      "csp-report.justgiving.com",
      "csp-report.staging.justgiving.com",
      "developer.justgiving.com",
      "fitness.justgiving.com",
      "fitness.staging.justgiving.com",
      "graphql.justgiving.com",
      "graphql.staging.justgiving.com",
      "help.justgiving.com",
      "id.justgiving.com",
      "id.staging.justgiving.com",
      "image.contact.justgiving.com",
      "info.justgiving.com",
      "internal.staging.justgiving.com",
      "justgiving.com",
      "media.justgiving.com",
      "mi.justgiving.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=9Ie7V9M2YudzHmywa873FdLnRJKZY57zwKHzQLgj_Kw",
    "miro-verification=0a2e1dbb2412c140c5fd914272eb7e9480bf1d6e",
    "google-site-verification=2l0z9VQCacbAFBgCmfbC47bnTeHQcq4LWOHoIzYG72Q",
    "docker-verification=eb8aed88-9460-4fab-9ef2-5ce59854ecc7",
    "lucid-verification=fcj@cjz6eat.zgj9WMQ"
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
      "aia_ocsp": "http://ocsp.r2m01.amazontrust.com",
      "serial": 13758950090290145763549439082221095006,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m01.amazontrust.com/r2m01.crl"
      ],
      "subject_dn": "3119301706035504030c102a2e6a757374676976696e672e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3031",
      "not_before": "20251103000000",
      "not_after": "20261201235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/",
      "/",
      "/user-account/",
      "/charity/search",
      "/fundraiser/search",
      "/charities/beta/account/login",
      "/share-success/",
      "/user-account/",
      "/charity/search",
      "/fundraiser/search",
      "/charities/beta/account/login",
      "/share-success/",
      "/user-account/",
      "/charity/search",
      "/fundraiser/search"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-3-169-55-71.tpe54.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=63072000; includeSubDomains; preload",
    "security_txt": "/.well-known/security.txt",
    "crl": {
      "url": "http://crl.r2m01.amazontrust.com/r2m01.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "elapsed_s": 14.2,
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
