# Security Audit Report — lmgtfy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://lmgtfy.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | lmgtfy.com |
| Test date | 2026-09-27 02:36 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **32** (High: 0, Medium: 0, Low: 5, Info: 27)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 12 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 15 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 16 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 19 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 20 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 21 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 22 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 23 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 24 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 25 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 26 | info | HTML7 | Insecure http:// references inside an HTTPS document | CWE-319 |
| 27 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 28 | info | HTML10 | Plaintext email addresses in the document | CWE-200 |
| 29 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 30 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |
| 31 | info | HTML16 | Inline event handlers in root document | CWE-79 |
| 32 | info | CT1 | 6 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

### 3. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Heroku
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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
- **Detail:** Header reveals: Heroku
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 12. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.lmgtfy.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 15. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 16. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (ird7x1t3e2eiea.lmgtfy.com and mk4dhf7p7n9kh9.lmgtfy.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=exfIwqRniT2rsPd2sDsMz5T19r0dqL7isibd--oVZLM; facebook-domain-verification=zcrcalu1jcrr2kzzo618qpli028r9l; google-site-verification=9hYmfh01IK_jYdX0bmBW8neNpJaBHFwlyeWgTC6jenU
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of lmgtfy.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 19. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but lmgtfy.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 20. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 2 disallow path(s), e.g. #, /*qtype=search
- **Recommendation:** Review disallowed paths; robots is not access control.

### 21. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 75.2.60.68 carries PTR a5a79225c76df2e39.awsglobalaccelerator.com. for lmgtfy.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 22. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xk62487fztkwi0.html -> 404; error page/headers match: Heroku.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 23. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for lmgtfy.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 24. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of lmgtfy.com loads 3 cross-origin script(s) without an integrity attribute, e.g. https://cdnjs.cloudflare.com/ajax/libs/select2/4.0.7/js/select2.min.js, https://www.googletagmanager.com/gtag/js?id=G-3PE7KJYKKC, https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 25. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on lmgtfy.com lists 40 <loc> URL(s); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 26. [INFO] Insecure http:// references inside an HTTPS document (`HTML7`)

- **CWE:** CWE-319
- **Detail:** Root document of lmgtfy.com references 6 distinct http:// URL(s) (e.g. http://a.adroll.com, http://lmgtfy.com, http://localhost:3000/short_urls); using them drops to unencrypted transport.
- **Recommendation:** Use https:// references or relative URLs.

### 27. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of lmgtfy.com references 12 distinct third-party registrable domains (e.g. w3.org, googlesyndication.com, twitter.com, cloudflare.com, adroll.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 28. [INFO] Plaintext email addresses in the document (`HTML10`)

- **CWE:** CWE-200
- **Detail:** Root document of lmgtfy.com contains 1 plaintext email address(es) (e.g. staff@lmgtfy.com); these are harvestable by bots.
- **Recommendation:** Use a contact form or mailto obfuscation for non-critical addresses.

### 29. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of lmgtfy.com contains wildcard SAN entry(ies) *.lmgtfy.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 30. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of lmgtfy.com discloses a 1-hop fronting chain (1.1 heroku-router); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

### 31. [INFO] Inline event handlers in root document (`HTML16`)

- **CWE:** CWE-79
- **Detail:** The root document of lmgtfy.com contains 40 inline event handler attribute(s); each is a DOM-level execution point that SRI does not constrain.
- **Recommendation:** Move handlers to external scripts where feasible and keep them covered by CSP.

### 32. [INFO] 6 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.lmgtfy.com, blog.lmgtfy.com, shop.lmgtfy.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "lmgtfy.com",
  "dns": {
    "a": [
      "75.2.60.68",
      "35.71.179.82",
      "99.83.220.108",
      "13.248.244.96"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)",
      "aspmx5.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)",
      "aspmx4.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "alt2.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "ns1.dnsimple.com.",
      "ns2.dnsimple.com.",
      "ns4.dnsimple.com.",
      "ns3.dnsimple.com."
    ],
    "caa": [],
    "spf": [
      "v=spf1 a mx include:_spf.google.com include:cmail1.com include:spf.mtasv.net ~all",
      "google-site-verification=exfIwqRniT2rsPd2sDsMz5T19r0dqL7isibd--oVZLM",
      "SEARCH_SAFER_INC_OWNS_LMGTFY_COM",
      "facebook-domain-verification=zcrcalu1jcrr2kzzo618qpli028r9l",
      "google-site-verification=9hYmfh01IK_jYdX0bmBW8neNpJaBHFwlyeWgTC6jenU",
      "google-site-verification=k61zckJgSciuGexCcNESZhBUNhs_72dxkZJRB9Yd1Oc",
      "google-site-verification=3XLdZhUjpU6Y-BX4FPOeXDUP7W3WnpqtzWEJy2Yx5yE"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.lmgtfy.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Aug  4 07:07:08 2026 GMT",
    "notAfter": "Nov  2 07:07:07 2026 GMT",
    "san": [
      "*.lmgtfy.com",
      "lmgtfy.com"
    ],
    "days_left": 36,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "75.2.60.68",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "LMGTFY - Let Me Google That For You"
  },
  "mixed_content": [
    "href=\"http://"
  ],
  "tech": [
    "Server: Heroku"
  ],
  "cookies": [
    {
      "samesite": "lax"
    },
    {
      "samesite": "lax"
    },
    {
      "domain": "lmgtfy.com",
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.lmgtfy.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://lmgtfy.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 6,
    "notable": [
      "api.lmgtfy.com",
      "blog.lmgtfy.com",
      "shop.lmgtfy.com"
    ],
    "sample": [
      "api.lmgtfy.com",
      "blog.lmgtfy.com",
      "lmgtfy.com",
      "report.lmgtfy.com",
      "shop.lmgtfy.com",
      "www.lmgtfy.com"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=exfIwqRniT2rsPd2sDsMz5T19r0dqL7isibd--oVZLM",
    "facebook-domain-verification=zcrcalu1jcrr2kzzo618qpli028r9l",
    "google-site-verification=9hYmfh01IK_jYdX0bmBW8neNpJaBHFwlyeWgTC6jenU",
    "google-site-verification=k61zckJgSciuGexCcNESZhBUNhs_72dxkZJRB9Yd1Oc",
    "google-site-verification=3XLdZhUjpU6Y-BX4FPOeXDUP7W3WnpqtzWEJy2Yx5yE"
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
      "serial": 475035078921985197444800400365023089827030,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://ye2.c.lencr.org/87.crl"
      ],
      "san": [
        "*.lmgtfy.com",
        "lmgtfy.com"
      ],
      "subject_dn": "3115301306035504030c0c2a2e6c6d677466792e636f6d",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303594532",
      "not_before": "20260804070708",
      "not_after": "20261102070707"
    }
  },
  "http2": {
    "robots_disallow": [
      "#",
      "/*qtype=search"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "a5a79225c76df2e39.awsglobalaccelerator.com."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=63072000; includeSubDomains",
    "sitemap": {
      "urls": 40,
      "indexes": 0
    },
    "crl": {
      "url": "http://ye2.c.lencr.org/87.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "x16": {
    "root_status": 200
  },
  "x17": {
    "wildcard_san": [
      "*.lmgtfy.com"
    ],
    "via": "1.1 heroku-router",
    "inline_handlers": 40
  },
  "elapsed_s": 38.6,
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
