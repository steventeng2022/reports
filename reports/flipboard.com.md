# Security Audit Report — flipboard.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://flipboard.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | flipboard.com |
| Test date | 2026-09-27 00:18 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 4, Info: 18)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | low | MAIL9 | DMARC enforces (p=quarantine) but has no reporting address (rua) | CWE-285 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 14 | low | CK8 | Session-like cookie with >=30-day lifetime | CWE-613 |
| 15 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 16 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 17 | info | REF1 | Referrer-Policy set to unsafe-url | CWE-200 |
| 18 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 19 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 20 | info | HTML7 | Insecure http:// references inside an HTTPS document | CWE-319 |
| 21 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 22 | info | CT1 | 12 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 5. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 6. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 7. [LOW] DMARC enforces (p=quarantine) but has no reporting address (rua) (`MAIL9`)

- **CWE:** CWE-285
- **Detail:** Without a rua= reporting address the policy cannot be tuned; mis-sends may be silently quarantined.
- **Recommendation:** Add a rua= reporting mailbox to the DMARC record.

### 8. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 9. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=EU2djlhiCyLFRE6dqL0HEIwLSclUSRLzkbvQ4ObXr7I; atlassian-domain-verification=dZ8g4eOwcpvhvx5AD10LH0gUSjKTUUgORwal07qANXl3412gq8; google-site-verification=eqogjmVDZB-9UMYUFvv5OlEO_a20KZadbY7DJw35Dys
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m01.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 19 disallow path(s), e.g. /, /analytics/, /api/, /bookmarklet/, /editor/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 54.192.248.101 carries PTR server-54-192-248-101.tpe53.r.cloudfront.net. for flipboard.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 14. [LOW] Session-like cookie with >=30-day lifetime (`CK8`)

- **CWE:** CWE-613
- **Detail:** Cookie '_csrf' on flipboard.com is session-like but carries a Max-Age/Expires lifetime of 30 days or more; a stolen cookie stays valid for a long window.
- **Recommendation:** Shorten session-cookie lifetime and/or require re-authentication for sensitive actions.

### 15. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xk1bx8r7ut9sxg.html -> 404; error page/headers match: CloudFront.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 16. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on flipboard.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 17. [INFO] Referrer-Policy set to unsafe-url (`REF1`)

- **CWE:** CWE-200
- **Detail:** Responses of flipboard.com set Referrer-Policy: unsafe-url; cross-origin requests leak the full URL (path/query) to third parties.
- **Recommendation:** Use strict-origin-when-cross-origin or a stricter policy.

### 18. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of flipboard.com loads 4 cross-origin script(s) without an integrity attribute, e.g. https://cdn.privacy-mgmt.com/unified/wrapperMessagingWithoutDetection.js, https://securepubads.g.doubleclick.net/tag/js/gpt.js, https://www.googletagmanager.com/gtag/js?id=G-F1YZDD86ZE; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 19. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on flipboard.com lists 2023 <loc> URL(s) across 2024 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 20. [INFO] Insecure http:// references inside an HTTPS document (`HTML7`)

- **CWE:** CWE-319
- **Detail:** Root document of flipboard.com references 4 distinct http:// URL(s) (e.g. http://b, http://cdn.flipboard.com/dev_O/insideflipboard/120318/YIR---US---1080X1080-A.jpg, http://cdn.flipboard.com/dev_O/insideflipboard/120318/YIR---US---800X600-A.jpg); using them drops to unencrypted transport.
- **Recommendation:** Use https:// references or relative URLs.

### 21. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of flipboard.com references 20 distinct third-party registrable domains (e.g. flip.it, wsj.net, s-nbcnews.com, schema.org, bbci.co.uk); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 22. [INFO] 12 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "flipboard.com",
  "dns": {
    "a": [
      "54.192.248.101",
      "54.192.248.119",
      "54.192.248.59",
      "54.192.248.48"
    ],
    "aaaa": [
      "2600:9000:202f:7a00:15:d33e:2640:93a1",
      "2600:9000:202f:c000:15:d33e:2640:93a1",
      "2600:9000:202f:b800:15:d33e:2640:93a1",
      "2600:9000:202f:9a00:15:d33e:2640:93a1",
      "2600:9000:202f:4600:15:d33e:2640:93a1",
      "2600:9000:202f:7600:15:d33e:2640:93a1",
      "2600:9000:202f:e000:15:d33e:2640:93a1",
      "2600:9000:202f:9c00:15:d33e:2640:93a1"
    ],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)",
      "aspmx5.googlemail.com (pref 30)",
      "aspmx4.googlemail.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx3.googlemail.com (pref 30)"
    ],
    "ns": [
      "ns-60.awsdns-07.com.",
      "ns-1756.awsdns-27.co.uk.",
      "ns-816.awsdns-38.net.",
      "ns-1510.awsdns-60.org."
    ],
    "caa": [
      "0 issue \"amazonaws.com\"",
      "0 issue \"digicert.com\"",
      "0 issue \"pki.goog\"",
      "0 issue \"amazon.com\"",
      "0 issue \"awstrust.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"amazontrust.com\""
    ],
    "spf": [
      "google-site-verification=EU2djlhiCyLFRE6dqL0HEIwLSclUSRLzkbvQ4ObXr7I",
      "_wpengine-sso-challenge.flipboard.com= 2KkDEiUGF0IvgPeA6uHIcV57z9H",
      "_wpengine-sso-challenge= 2KkDEiUGF0IvgPeA6uHIcV57z9H",
      "atlassian-domain-verification=dZ8g4eOwcpvhvx5AD10LH0gUSjKTUUgORwal07qANXl3412gq8IYKOlI4oa4llnl",
      "google-site-verification=eqogjmVDZB-9UMYUFvv5OlEO_a20KZadbY7DJw35Dys",
      "google-site-verification=47g-PnfQPJHjb8Ze5YYF-hF2ABg67yFQc-kwrSv8PAY",
      "have-i-been-pwned-verification=6b731851fd4ef8a6d49f6f8ff8f3eed4",
      "google-site-verification=9rExE5dYg3CPZ3GFGvrkj2MbbKAkdHHH5aRUYSnq9w4",
      "google-site-verification=196ICmalqDggbij227IKpDuO8wjKIGJOoWQUKVR0B0U",
      "v=spf1 include:servers.mcsv.net include:sendgrid.net include:_spf.google.com -all",
      "google-site-verification=BqjKftnKldO1vP49cSkz2ryHMLPk5y3V6-JlkIhUo1U",
      "anthropic-domain-verification-1avd9b=GWlaVK7cM1UrnAecUR0PhzRI7"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.flipboard.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Feb 11 00:00:00 2026 GMT",
    "notAfter": "Mar 11 23:59:59 2027 GMT",
    "san": [
      "*.flipboard.com",
      "www.flipboard.com",
      "flipboard.com"
    ],
    "days_left": 165,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.101",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Flipboard: Your Social Magazine"
  },
  "mixed_content": [],
  "cookies": [
    {
      "domain": "flipboard.com"
    },
    {},
    {}
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.flipboard.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://flipboard.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 403,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 12,
    "notable": [],
    "sample": [
      "about.flipboard.com",
      "analytics.flipboard.com",
      "applink.flipboard.com",
      "engineering.flipboard.com",
      "flipboard.com",
      "fliptest.flipboard.com",
      "pea.flipboard.com",
      "production-v3.eks.flipboard.com",
      "production-v4.eks.flipboard.com",
      "sli.flipboard.com",
      "wp.flipboard.com",
      "www.flipboard.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=EU2djlhiCyLFRE6dqL0HEIwLSclUSRLzkbvQ4ObXr7I",
    "atlassian-domain-verification=dZ8g4eOwcpvhvx5AD10LH0gUSjKTUUgORwal07qANXl3412gq8",
    "google-site-verification=eqogjmVDZB-9UMYUFvv5OlEO_a20KZadbY7DJw35Dys",
    "google-site-verification=47g-PnfQPJHjb8Ze5YYF-hF2ABg67yFQc-kwrSv8PAY",
    "have-i-been-pwned-verification=6b731851fd4ef8a6d49f6f8ff8f3eed4"
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
      "serial": 6671323273794328607741956835867547980,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m01.amazontrust.com/r2m01.crl"
      ],
      "subject_dn": "3118301606035504030c0f2a2e666c6970626f6172642e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3031",
      "not_before": "20260211000000",
      "not_after": "20270311235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/analytics/",
      "/api/",
      "/bookmarklet/",
      "/editor/",
      "/getflipit",
      "/logout",
      "/notifications",
      "/post",
      "/oauth/",
      "/redirect?",
      "/search/",
      "/signout",
      "/static/ebsa/",
      "/static/gfs/"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-54-192-248-101.tpe53.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "sitemap": {
      "urls": 2023,
      "indexes": 2024
    },
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
  "elapsed_s": 20.6,
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
