# Security Audit Report — fastcompany.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://fastcompany.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | fastcompany.com |
| Test date | 2026-09-27 02:28 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 2, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 16 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 17 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 18 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 19 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 20 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |
| 21 | info | CT1 | 25 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

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
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=2wRqY6IrIINLY7B8Qcp-qur9HsiRTO04g4gwsMmFy3; _globalsign-domain-verification=klUJkI4MZw-0elRtIBbVGs7d-e1CPM16mbnrVrKORw; google-site-verification=W3-NcdnZXk2Yl4BinFIa3fKWuwJXgC4x-7a7LuiRLHI
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2026q2 -> http-400
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 38 disallow path(s), e.g. /rest, /rest, /rest, /rest, /
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for fastcompany.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 16. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on fastcompany.com lists 1719 <loc> URL(s) across 1720 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 17. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on fastcompany.com identify the edge as Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 18. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of fastcompany.com contains wildcard SAN entry(ies) *.fast-co.net, *.fastcocreate.com, *.fastcodesign.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 19. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of fastcompany.com is http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2026q2; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 20. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of fastcompany.com discloses a 1-hop fronting chain (1.1 varnish); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

### 21. [INFO] 25 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: auth.fastcompany.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "fastcompany.com",
  "dns": {
    "a": [
      "151.101.65.54",
      "151.101.1.54",
      "151.101.129.54",
      "151.101.193.54"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx1-us1.ppe-hosted.com (pref 5)",
      "mx2-us1.ppe-hosted.com (pref 10)"
    ],
    "ns": [
      "ns-1872.awsdns-42.co.uk.",
      "ns-27.awsdns-03.com.",
      "ns-715.awsdns-25.net.",
      "ns-1515.awsdns-61.org."
    ],
    "caa": [],
    "spf": [
      "_globalsign-domain-verification=2wRqY6IrIINLY7B8Qcp-qur9HsiRTO04g4gwsMmFy3",
      "ca3-e2ea934ff9d1486f9910f9c81761fa99 MS=EA6BD12E4042FBE98C6039D238059CE6AE1E347F",
      "_globalsign-domain-verification=klUJkI4MZw-0elRtIBbVGs7d-e1CPM16mbnrVrKORw",
      "buu/MrJiTMBBRF3W3ASumwqjDif644jK3TX5YPk+D5g=",
      "YixrMKRsWOSKfzWgsRRi6NVmxyB4qG17n1iLIxsXxfXzkNFJKBVZXwdtDiU+ZorIZaJZCL/qpzsHemJdhnHfSw==",
      "google-site-verification=W3-NcdnZXk2Yl4BinFIa3fKWuwJXgC4x-7a7LuiRLHI",
      "ca3-05cc9f378ce24610b09ea1bd36527e63",
      "MS=ms42877241",
      "_globalsign-domain-verification=3Z8bdt8iCWVQuFZDQkoKYwCoWBX6gyXdBAZWw1GzmI",
      "_globalsign-domain-verification=vgLXYEFUoOerT8uIZkhvA3Un5juG_KyzM_4G3EFw0_",
      "google-site-verification=eO1qsJOo2gALpVdcso2IuN6exMycZNqDOO1XpeqTC_A",
      "google-site-verification=PY9DET9Or1b_mkw2Xkgs3TBQaPEHmumzBTOk3_QaZ18",
      "v=spf1 a:dispatch-us.ppe-hosted.com include:_spf.google.com include:spf.mandrillapp.com include:amazonses.com include:spf.protection.outlook.com include:mail.zendesk.com ~all",
      "ZOOM_verify_3AkoDfohygJsFa5Q70IqZB",
      "Fastly-322681-041220-2816749",
      "_globalsign-domain-verification=UNpHzsP3DfgbAxW7_LaHmV-0basWFjytZ3uVL4DUzq",
      "tollbit-domain-verification=96220e3137d5f1dc634856c5e2b7a7ba5f57096a7179bf1fdaa43239646c5108"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc@fastcompany.com; ruf=mailto:dmarc@fastcompany.com; aspf=s;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.fast-co.net",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2026 Q2",
    "notBefore": "Jul 15 19:31:45 2026 GMT",
    "notAfter": "Jan 30 18:31:45 2027 GMT",
    "san": [
      "*.fast-co.net",
      "*.fastcocreate.com",
      "*.fastcodesign.com",
      "*.fastcoexist.com",
      "*.fastcolabs.com",
      "*.fastcompany.com",
      "*.fastcompany.net",
      "*.inc.com",
      "*.node.inc.com",
      "events.festival.fastcompany.com",
      "events.grill.fastcompany.com",
      "fast-co.net",
      "fastcodesign.com",
      "fastcompany.com",
      "fcimpactcouncil.com",
      "inc.com",
      "one.mansueto.com",
      "static.mvdigitalmedia.com",
      "www.fcimpactcouncil.com",
      "www.mansueto.com",
      "mansueto.com",
      "*.dev.inc.com"
    ],
    "days_left": 125,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.65.54",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.fastcompany.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.fastcompany.com/"
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
    "source": "certspotter",
    "count": 25,
    "notable": [
      "auth.fastcompany.com"
    ],
    "sample": [
      "apply.fastcompany.com",
      "auth.fastcompany.com",
      "board-dev.fastcompany.com",
      "board-stg.fastcompany.com",
      "board.fastcompany.com",
      "c783.fastcompany.com",
      "events.fastcompany.com",
      "events.festival.fastcompany.com",
      "events.grill.fastcompany.com",
      "executive-board.fastcompany.com",
      "fastcompany.com",
      "fc-resources.fastcompany.com",
      "go.fastcompany.com",
      "gtm.fastcompany.com",
      "kudos.fastcompany.com",
      "magazine.fastcompany.com",
      "mediakit.fastcompany.com",
      "portfolio.fastcompany.com",
      "register.fastcompany.com",
      "social.fastcompany.com"
    ]
  },
  "apex_txt": [
    "_globalsign-domain-verification=2wRqY6IrIINLY7B8Qcp-qur9HsiRTO04g4gwsMmFy3",
    "_globalsign-domain-verification=klUJkI4MZw-0elRtIBbVGs7d-e1CPM16mbnrVrKORw",
    "google-site-verification=W3-NcdnZXk2Yl4BinFIa3fKWuwJXgC4x-7a7LuiRLHI",
    "_globalsign-domain-verification=3Z8bdt8iCWVQuFZDQkoKYwCoWBX6gyXdBAZWw1GzmI",
    "_globalsign-domain-verification=vgLXYEFUoOerT8uIZkhvA3Un5juG_KyzM_4G3EFw0_"
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
      "aia_ocsp": "http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2026q2",
      "serial": 2382458787401433744799743967305798194,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.globalsign.com/ca/gsatlasr3dvtlsca2026q2.crl"
      ],
      "san": [
        "*.fast-co.net",
        "*.fastcocreate.com",
        "*.fastcodesign.com",
        "*.fastcoexist.com",
        "*.fastcolabs.com",
        "*.fastcompany.com",
        "*.fastcompany.net",
        "*.inc.com",
        "*.node.inc.com",
        "events.festival.fastcompany.com",
        "events.grill.fastcompany.com",
        "fast-co.net",
        "fastcodesign.com",
        "fastcompany.com",
        "fcimpactcouncil.com",
        "inc.com",
        "one.mansueto.com",
        "static.mvdigitalmedia.com",
        "www.fcimpactcouncil.com",
        "www.mansueto.com"
      ],
      "subject_dn": "3116301406035504030c0d2a2e666173742d636f2e6e6574",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312e302c06035504031325476c6f62616c5369676e2041746c617320523320445620544c532043412032303236205132",
      "not_before": "20260715193145",
      "not_after": "20270130183145"
    },
    "ocsp": "http-400"
  },
  "http2": {
    "robots_disallow": [
      "/rest",
      "/rest",
      "/rest",
      "/rest",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.fastcompany.com/",
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
    "sitemap": {
      "urls": 1719,
      "indexes": 1720
    },
    "crl": {
      "url": "http://crl.globalsign.com/ca/gsatlasr3dvtlsca2026q2.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "cdn": [
      "Fastly"
    ]
  },
  "x17": {
    "wildcard_san": [
      "*.fast-co.net",
      "*.fastcocreate.com",
      "*.fastcodesign.com",
      "*.fastcoexist.com",
      "*.fastcolabs.com"
    ],
    "ocsp_http": "http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2026q2",
    "via": "1.1 varnish"
  },
  "elapsed_s": 21.0,
  "rechecked": "2026-09-27 02:16 UTC"
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
- re-run #16 passive additions: the edge/protocol angles read the alt-svc, server-timing and CDN-identification headers from the one root GET; the preconnect/dns-prefetch, base-href and noindex angles parse the already-fetched root document; the TLS 1.2-only ceiling, SHA-1 signature and weak-key angles use the certificate evidence the base TLS check already captured; the only extra requests this pass are two read-only GETs (/.well-known/jwks.json and /.well-known/change-password).
- re-run #17 passive additions: the retired-header angles (Public-Key-Pins, Expect-CT, X-Permitted-Cross-Domain-Policies, Via, COOP/COEP, Permissions-Policy) read from the one root GET; the wildcard SAN, http:// OCSP and 398-day-cap angles use the certificate evidence the base TLS check already captured (SAN now harvested from the existing DER); the only extra requests this pass are three read-only GETs (/.well-known/dpop-jwks.json, /.well-known/origin-rsa-keys.json, /.well-known/llms.txt).
- Findings are reported against the public program scope; submission through the program tracker is pending.
