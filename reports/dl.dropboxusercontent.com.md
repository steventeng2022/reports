# Security Audit Report — dl.dropboxusercontent.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dl.dropboxusercontent.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | dl.dropboxusercontent.com |
| Test date | 2026-09-27 02:25 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 14 | info | HTML14 | Public root document marked noindex | CWE-200 |
| 15 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 16 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 17 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |
| 18 | info | CT1 | 1 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: envoy
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: envoy
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (5o0buaz29mx71k.dl.dropboxusercontent.com and qxuf5hqdhb9v4r.dl.dropboxusercontent.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but dl.dropboxusercontent.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The dl.dropboxusercontent.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 14. [INFO] Public root document marked noindex (`HTML14`)

- **CWE:** CWE-200
- **Detail:** The root document of dl.dropboxusercontent.com is marked noindex (meta robots or X-Robots-Tag); a public homepage that is not indexable is a posture anomaly worth reviewing.
- **Recommendation:** Confirm the noindex directive is intentional.

### 15. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of dl.dropboxusercontent.com contains wildcard SAN entry(ies) *.dl-au.app.dropboxusercontent.com, *.dl-au.dropboxusercontent.com, *.dl-eu.app.dropboxusercontent.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 16. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of dl.dropboxusercontent.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 17. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of dl.dropboxusercontent.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

### 18. [INFO] 1 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "dl.dropboxusercontent.com",
  "dns": {
    "a": [
      "162.125.85.15"
    ],
    "aaaa": [
      "2620:100:6035:15::a27d:550f"
    ],
    "cname": "edge-block-www-env.dropbox-dns.com.",
    "mx": [],
    "ns": [],
    "caa": [],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Francisco, organizationName=Dropbox, Inc, commonName=*.dl-au.app.dropboxusercontent.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Sep 25 00:00:00 2026 GMT",
    "notAfter": "Mar 10 23:59:59 2027 GMT",
    "san": [
      "*.dl-au.app.dropboxusercontent.com",
      "*.dl-au.dropboxusercontent.com",
      "*.dl-eu.app.dropboxusercontent.com",
      "*.dl-eu.dropboxusercontent.com",
      "*.dl-jp.app.dropboxusercontent.com",
      "*.dl-jp.dropboxusercontent.com",
      "*.dl-uk.app.dropboxusercontent.com",
      "*.dl-uk.dropboxusercontent.com",
      "*.dl-web-au.app.dropbox.com",
      "*.dl-web-eu.app.dropbox.com",
      "*.dl-web-jp.app.dropbox.com",
      "*.dl-web-uk.app.dropbox.com",
      "*.dl-web.app.dropbox.com",
      "*.dl.app.dropboxusercontent.com",
      "*.dl.dropboxusercontent.com",
      "dl-au.dropbox.com",
      "dl-au.dropboxusercontent.com",
      "dl-eu.dropbox.com",
      "dl-eu.dropboxusercontent.com",
      "dl-jp.dropbox.com",
      "dl-jp.dropboxusercontent.com",
      "dl-uk.dropbox.com",
      "dl-uk.dropboxusercontent.com",
      "dl-web-au.dropbox.com",
      "dl-web-eu.dropbox.com",
      "dl-web-jp.dropbox.com",
      "dl-web-uk.dropbox.com",
      "dl-web.dropbox.com",
      "dl.dropbox.com",
      "dl.dropboxusercontent.com",
      "files-au.dropbox.com",
      "files-eu.dropbox.com",
      "files-jp.dropbox.com",
      "files-uk.dropbox.com",
      "files.dropbox.com"
    ],
    "days_left": 164,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "162.125.85.15",
    "open": []
  },
  "https": {
    "status": 404,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: envoy"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.dl.dropboxusercontent.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://dl.dropboxusercontent.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 404,
    "/sitemap.xml": 404,
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
    "count": 1,
    "notable": [],
    "sample": [
      "dl.dropboxusercontent.com"
    ]
  },
  "wildcard_dns": true,
  "cname_chain": [
    "edge-block-www-env.dropbox-dns.com"
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
      "serial": 5104460950802433046197580097171651322,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
        "http://crl4.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl"
      ],
      "san": [
        "*.dl-au.app.dropboxusercontent.com",
        "*.dl-au.dropboxusercontent.com",
        "*.dl-eu.app.dropboxusercontent.com",
        "*.dl-eu.dropboxusercontent.com",
        "*.dl-jp.app.dropboxusercontent.com",
        "*.dl-jp.dropboxusercontent.com",
        "*.dl-uk.app.dropboxusercontent.com",
        "*.dl-uk.dropboxusercontent.com",
        "*.dl-web-au.app.dropbox.com",
        "*.dl-web-eu.app.dropbox.com",
        "*.dl-web-jp.app.dropbox.com",
        "*.dl-web-uk.app.dropbox.com",
        "*.dl-web.app.dropbox.com",
        "*.dl.app.dropboxusercontent.com",
        "*.dl.dropboxusercontent.com",
        "dl-au.dropbox.com",
        "dl-au.dropboxusercontent.com",
        "dl-eu.dropbox.com",
        "dl-eu.dropboxusercontent.com",
        "dl-jp.dropbox.com"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d53616e204672616e636973636f31153013060355040a130c44726f70626f782c20496e63312b302906035504030c222a2e646c2d61752e6170702e64726f70626f7875736572636f6e74656e742e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473320544c532045434320534841333834203230323020434131",
      "not_before": "20260925000000",
      "not_after": "20270310235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 404
  },
  "x13": {
    "root_status": 404,
    "http_status": 301,
    "p404_status": 404,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 404,
    "hsts": "max-age=31536000; includeSubDomains; preload",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 404
  },
  "x16": {
    "root_status": 404,
    "noindex": true
  },
  "x17": {
    "wildcard_san": [
      "*.dl-au.app.dropboxusercontent.com",
      "*.dl-au.dropboxusercontent.com",
      "*.dl-eu.app.dropboxusercontent.com",
      "*.dl-eu.dropboxusercontent.com",
      "*.dl-jp.app.dropboxusercontent.com"
    ],
    "ocsp_http": "http://ocsp.digicert.com"
  },
  "elapsed_s": 16.9,
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
