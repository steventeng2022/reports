# Security Audit Report — hbr.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hbr.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hbr.org |
| Test date | 2026-09-27 00:21 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 8 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 9 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 15 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 16 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 17 | info | CT1 | 26 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 18 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=7776000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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

### 7. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 8. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 9. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (pq7f19t8x5oy0a.hbr.org and jab3ocyfbmxdqg.hbr.org) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=ikLo_eYH7jY56yB4qtVoDTxY9WUWl7NkUEsM-UB6DT0; google-site-verification=0fyEgLpijqbt_OMG0ncBIK4G153eKqHF7UeGfTZgZk0; knowbe4-site-verification=f00a4d6e618b4a00b6f39e0b4c9e093f
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but hbr.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 26 disallow path(s), e.g. /resources/, /fastanswers, /my-library*, /email-colleague/, /add-to-cart/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 65.9.180.70 carries PTR server-65-9-180-70.tpe53.r.cloudfront.net. for hbr.org.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 15. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on hbr.org; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 16. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of hbr.org references 10 distinct third-party registrable domains (e.g. w3.org, harvardbusiness.org, geoip-js.com, zendesk.com, harvard.edu); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 17. [INFO] 26 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: login.hbr.org, login.qa.hbr.org, store.hbr.org, store.qa.hbr.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 18. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: login.hbr.org; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "hbr.org",
  "dns": {
    "a": [
      "65.9.180.70",
      "65.9.180.27",
      "65.9.180.29",
      "65.9.180.80"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "usb-smtp-inbound-2.mimecast.com (pref 10)",
      "usb-smtp-inbound-1.mimecast.com (pref 10)"
    ],
    "ns": [
      "ns-469.awsdns-58.com.",
      "ns-1877.awsdns-42.co.uk.",
      "ns-1175.awsdns-18.org.",
      "ns-604.awsdns-11.net."
    ],
    "caa": [
      "0 issue \"amazonaws.com\"",
      "0 issue \"digicert.com\"",
      "0 issue \"amazontrust.com\"",
      "0 issue \"sectigo.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 iodef \"mailto:hostmaster@harvardbusiness.org\"",
      "0 issue \"amazon.com\"",
      "0 issue \"awstrust.com\""
    ],
    "spf": [
      "Wo71J1PNbWKkAikjb4WeqxCjBcNQwf6hcll0LJM6s9peRMF1ImcaCENQfddffLROaJY6wZHW2jrUsDNXC38vjg==",
      "lyncdiscover = seh3q1rpvadu98fpk213q7htq2",
      "google-site-verification=ikLo_eYH7jY56yB4qtVoDTxY9WUWl7NkUEsM-UB6DT0",
      "google-site-verification=0fyEgLpijqbt_OMG0ncBIK4G153eKqHF7UeGfTZgZk0",
      "knowbe4-site-verification=f00a4d6e618b4a00b6f39e0b4c9e093f",
      "webexdomainverification.4C675B8B1892B136E053AB06FC0A3F65=7b2ac320-8920-4cf1-826d-975f96f199cb",
      "sip=m699vbpan7kdoitobogsq38e1k",
      "ciscocidomainverification=3a5e2e428cc891b6aef0b7598537338dd5c2bf8fe96326d58d87f62324dd9733",
      "extensis-domain-verification=3decd987-0352-469b-8111-a273b429588a",
      "v=spf1 ip4:167.89.5.215 include:hbsp.harvard.edu include:amazonses.com include:u12602457.wl208.sendgrid.net include:aspmx.sailthru.com include:_spf.bigcommerce.com ~all",
      "docusign=59df337d-04fe-422f-bd8e-438fc3e80d21",
      "facebook-domain-verification=hvrm85rd5hvr18o50vzpd1lprkjg76",
      "_1nl5kysnqxswpmo75e1u1fdcbs0fptr",
      "google-site-verification=P1JGD_hnkAqlxSPmsFW_M2nifpmJC2iBjnfmKi1uJCc",
      "google-site-verification=o-E502ZnlfSSAM2JRb0RUfIxROmYDcYVOZnzlVRknS0",
      "onetrust-domain-verification=0df7d79642a64b338bb91818045b158d",
      "MS=ms51679339",
      "openai-domain-verification=dv-yzIW4FvevpXrgKYrQ9Ndlm4V",
      "smartsheet-site-validation=76f6Fdn8EnnOgbwX-KcCnJ5Nj66wRUeo",
      "atlassian-domain-verification=5VnB9cXf8cZ+rqMksjlq1KyEzUSjGsBJ5irmtvOZtpwtq6AsKSs+jGHcKUhotODA"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:ufwln6jz@ag.dmarcian.com; ruf=mailto:ufwln6jz@fr.dmarcian.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.hbr.org",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Sep 15 00:00:00 2026 GMT",
    "notAfter": "Mar 31 23:59:59 2027 GMT",
    "san": [
      "*.hbr.org",
      "hbr.org"
    ],
    "days_left": 185,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "65.9.180.70",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Harvard Business Review - Ideas and Advice for Leaders"
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.hbr.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://hbr.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 403,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 26,
    "notable": [
      "login.hbr.org",
      "login.qa.hbr.org",
      "store.hbr.org",
      "store.qa.hbr.org"
    ],
    "sample": [
      "advisorycouncil.hbr.org",
      "assessments.hbr.org",
      "audio.hbr.org",
      "coveo-analytics-qa.hbr.org",
      "coveo-analytics.hbr.org",
      "coveo-search-qa.hbr.org",
      "coveo-search.hbr.org",
      "execstrategy-dev.hbr.org",
      "execstrategy-sand.hbr.org",
      "execstrategy-stage.hbr.org",
      "execstrategy.hbr.org",
      "hbr.org",
      "lab.hbr.org",
      "link.emails.hbr.org",
      "link.hbr.org",
      "link.qa.hbr.org",
      "login.hbr.org",
      "login.qa.hbr.org",
      "qa.hbr.org",
      "research.hbr.org"
    ],
    "dangling": [
      "login.hbr.org"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=ikLo_eYH7jY56yB4qtVoDTxY9WUWl7NkUEsM-UB6DT0",
    "google-site-verification=0fyEgLpijqbt_OMG0ncBIK4G153eKqHF7UeGfTZgZk0",
    "knowbe4-site-verification=f00a4d6e618b4a00b6f39e0b4c9e093f",
    "webexdomainverification.4C675B8B1892B136E053AB06FC0A3F65=7b2ac320-8920-4cf1-826d",
    "ciscocidomainverification=3a5e2e428cc891b6aef0b7598537338dd5c2bf8fe96326d58d87f6"
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
      "serial": 2736116409129541134747334836127673898,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "subject_dn": "3112301006035504030c092a2e6862722e6f7267",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20260915000000",
      "not_after": "20270331235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/resources/",
      "/fastanswers",
      "/my-library*",
      "/email-colleague/",
      "/add-to-cart/",
      "/login*",
      "/shopping-cart/",
      "/shipping-payment",
      "/review-order",
      "/order/thank-you/",
      "/content/ipad/",
      "/newsletters*",
      "/product/recommended*",
      "/webinar-assessment",
      "/search*"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-65-9-180-70.tpe53.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 301,
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
    "hsts": "max-age=7776000",
    "crl": {
      "url": "http://crl.r2m04.amazontrust.com/r2m04.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
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
