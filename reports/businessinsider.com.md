# Security Audit Report — businessinsider.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://businessinsider.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | businessinsider.com |
| Test date | 2026-09-27 01:12 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 5, Info: 19)

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
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 18 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 19 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 20 | info | HTML7 | Insecure http:// references inside an HTTPS document | CWE-319 |
| 21 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |
| 22 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 23 | info | CT1 | 37 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 24 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
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
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

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
- **Detail:** Apex TXT records with verification/token content: lucidlink-verification=H13VJ94S9GRFM6ZX539Q5EB8MG; openai-domain-verification=dv-gEVeLfZWhh8fDqhgX7be0VGh; google-site-verification=HA4gcc-DAPuEX5Z3gfg-LTrtafWTIr40orlRHKZSLy0
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2026q1 -> http-400
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but businessinsider.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 72 disallow path(s), e.g. /*?utm_campaign=Monitor&, /adframe, /afp$, /ajax/, /answers$
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for businessinsider.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 18. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The businessinsider.com certificate lists an AIA OCSP responder (http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2026q1) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 19. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on businessinsider.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of businessinsider.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 20. [INFO] Insecure http:// references inside an HTTPS document (`HTML7`)

- **CWE:** CWE-319
- **Detail:** Root document of businessinsider.com references 4 distinct http:// URL(s) (e.g. http://static.businessinsider.com/assets/css/shared.css, http://static.businessinsider.com/assets/images/logos/logo-tbi.gif, http://www.w3.org/1999/xhtml); using them drops to unencrypted transport.
- **Recommendation:** Use https:// references or relative URLs.

### 21. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to businessinsider.com negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

### 22. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on businessinsider.com identify the edge as Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 23. [INFO] 37 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: gcp.businessinsider.com, it.businessinsider.com, my.businessinsider.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 24. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: gcp.businessinsider.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "businessinsider.com",
  "dns": {
    "a": [
      "151.101.193.171",
      "151.101.1.171",
      "151.101.129.171",
      "151.101.65.171"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)"
    ],
    "ns": [
      "dns2.p03.nsone.net.",
      "dns1.p03.nsone.net.",
      "ns11.constellix.com.",
      "dns4.p03.nsone.net.",
      "ns41.constellix.net.",
      "ns21.constellix.com.",
      "ns61.constellix.net.",
      "ns31.constellix.com.",
      "dns3.p03.nsone.net.",
      "ns51.constellix.net."
    ],
    "caa": [],
    "spf": [
      "lucidlink-verification=H13VJ94S9GRFM6ZX539Q5EB8MG",
      "MS=49384EFC2AA5C920CC726E72850EA7250E18356F",
      "openai-domain-verification=dv-gEVeLfZWhh8fDqhgX7be0VGh",
      "google-site-verification=HA4gcc-DAPuEX5Z3gfg-LTrtafWTIr40orlRHKZSLy0",
      "facebook-domain-verification=jz79wu26i92i5zpxpqra4s1p1ois9j",
      "atlassian-domain-verification=EnHue3UwYSfo4DXgk/Bvg3WcQ2JVjyt6zf38Dox2HOZXITSpjtg1iNnMasAJ3GsD",
      "openai-domain-verification=dv-jTz4KfMtiA6SiWiVpka2QDFr",
      "google-site-verification=lhkw5_yE2VpatfjtNqFeTXshSdHOmye2FSHCz4_IZwE",
      "google-site-verification=dsTQoEYtkhKJUiHaf7NXBGBP5wRxmQ2ia56y9UnTeZc",
      "v=spf1 include:_spf.google.com include:mail.zendesk.com include:_spf.salesforce.com ~all",
      "_globalsign-domain-verification=O81xyb7YxpdGeHWkniit_VBT4vTXz9__NFrNMoTwFg",
      "slack-domain-verification=p1y98UQQ7JwUhAuHWXgLsJqM1VDqn56eErx227bu",
      "00Dd0000000cyqM=1TBQK00000000rF",
      "google-site-verification=MeuJIyKOrXf6e1Foju5Tqkzoms8KH0IoP01G5KhB-m8",
      "apple-domain-verification=G59n_HIhMNvtkyEDlx0g1LdxhRL8neVCOkZ-NcIa0cQ",
      "google-site-verification=5khzg7Aljjht1XobmkoQeX_2L4E5UJO9C1Z9_zfFTYs",
      "ZOOM_verify_BiuNcpuc03G4NjRCC8crLr",
      "zapier-domain-verification-challenge=e10fad84-5944-470d-ae77-5d7697d0af05",
      "asv=4f7bed0ed9307319569dca0dc413d303",
      "google-site-verification=6siIDX8Eh0aPCTSxDF2-GFuuFff1H1aPGm3SfPvP7aI",
      "canva-site-verification=yOD8mjIYFWLM6qJQW-rwgg",
      "atlassian-domain-verification=EnHue3UwYSfo4DXgk/Bvg3WcQ2JVjyt6zf38Dox2HOZXlTSpjtg1iNnMasAJ3GsD",
      "google-site-verification=hVwc4FIT_C_8DNSPQSBmv84brU443LMUlfiyDqrByVA",
      "google-site-verification=E4A9jU1go8SQoOYqjwybQIyUhIqPRDUF2Fu5nYC77oM",
      "globalsign-domain-verification=qhllLTVNbc63_k7N_0u2VjkgHnq48qKQ8gKVvHWkHI"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-reports@insider.com; ruf=mailto:dmarc-reports@insider.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=businessinsider.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2026 Q1",
    "notBefore": "Feb 11 19:00:25 2026 GMT",
    "notAfter": "Mar 15 19:00:24 2027 GMT",
    "san": [
      "businessinsider.com"
    ],
    "days_left": 169,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "151.101.193.171",
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
      "origin": "https://sub.businessinsider.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.businessinsider.com/"
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
    "count": 37,
    "notable": [
      "gcp.businessinsider.com",
      "it.businessinsider.com",
      "my.businessinsider.com"
    ],
    "sample": [
      "account-dev.businessinsider.com",
      "account.businessinsider.com",
      "advertising.businessinsider.com",
      "africa.businessinsider.com",
      "businessinsider.com",
      "comments.businessinsider.com",
      "consent.markets.businessinsider.com",
      "coupons.businessinsider.com",
      "e.businessinsider.com",
      "gcp.businessinsider.com",
      "i-dev-cf.businessinsider.com",
      "info.businessinsider.com",
      "ing-images.businessinsider.com",
      "it.businessinsider.com",
      "l.businessinsider.com",
      "live.businessinsider.com",
      "login-dev.businessinsider.com",
      "markets.businessinsider.com",
      "my-dev.businessinsider.com",
      "my.businessinsider.com"
    ],
    "dangling": [
      "gcp.businessinsider.com"
    ]
  },
  "apex_txt": [
    "lucidlink-verification=H13VJ94S9GRFM6ZX539Q5EB8MG",
    "openai-domain-verification=dv-gEVeLfZWhh8fDqhgX7be0VGh",
    "google-site-verification=HA4gcc-DAPuEX5Z3gfg-LTrtafWTIr40orlRHKZSLy0",
    "facebook-domain-verification=jz79wu26i92i5zpxpqra4s1p1ois9j",
    "atlassian-domain-verification=EnHue3UwYSfo4DXgk/Bvg3WcQ2JVjyt6zf38Dox2HOZXITSpjt"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": "http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2026q1",
      "serial": 2067354918998838162204996436775261511,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.globalsign.com/ca/gsatlasr3dvtlsca2026q1.crl"
      ],
      "subject_dn": "311c301a06035504030c13627573696e657373696e73696465722e636f6d",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312e302c06035504031325476c6f62616c5369676e2041746c617320523320445620544c532043412032303236205131",
      "not_before": "20260211190025",
      "not_after": "20270315190024"
    },
    "ocsp": "http-400"
  },
  "http2": {
    "robots_disallow": [
      "/*?utm_campaign=Monitor&",
      "/adframe",
      "/afp$",
      "/ajax/",
      "/answers$",
      "/archives",
      "/associated-press$",
      "/authentication$",
      "/author/*/date",
      "/author/*/mostread",
      "/categories",
      "/cms/",
      "/comments$",
      "/cross-domain$",
      "/document/"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.businessinsider.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=31536000",
    "crl": {
      "url": "http://crl.globalsign.com/ca/gsatlasr3dvtlsca2026q1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "cipher_ver": "TLSv1.2",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "cdn": [
      "Fastly"
    ]
  },
  "elapsed_s": 30.7,
  "rechecked": "2026-09-27 01:08 UTC"
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
- Findings are reported against the public program scope; submission through the program tracker is pending.
