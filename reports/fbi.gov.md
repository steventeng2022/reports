# Security Audit Report — fbi.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://fbi.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | fbi.gov |
| Test date | 2026-09-27 01:19 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 3, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 19 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 20 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 21 | info | CT1 | 424 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 22 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.148.244:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.148.244:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=L8cauHJF4MANoTCkMbrLkAVfHBta28ctva9n1IDekTo; apple-domain-verification=oOspXl6Jvnx9HzLM; google-site-verification=uTH4Vg-Xcc9hTqSdeThbT9UnYvuphObtVSpCEgaGr78
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of fbi.gov has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 15 disallow path(s), e.g. #, /@@search?, /search?, /*atct_album_view$, /*folder_factories$
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on fbi.gov indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 19. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '_cfuvid' set on fbi.gov indicates Cloudflare visitor cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 20. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of fbi.gov carries alt-svc h3=":443"; ma=86400; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 21. [INFO] 424 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: alpha-sifts-staging.apps.dcap.fbi.gov, alpha-sifts.apps.dcap.fbi.gov, api.fbi.gov, api.sos.fbi.gov, avalanche.dv.apps.dcap.fbi.gov, avalanche.va.apps.dcap.fbi.gov, circe.va.apps.dcap.fbi.gov, denali.dv.apps.dcap.fbi.gov, denali.va.apps.dcap.fbi.gov, frost.va.apps.dcap.fbi.gov
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 22. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: alpha-sifts-staging.apps.dcap.fbi.gov, alpha-sifts.apps.dcap.fbi.gov, api.sos.fbi.gov; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "fbi.gov",
  "dns": {
    "a": [
      "104.16.148.244",
      "104.16.149.244"
    ],
    "aaaa": [
      "2606:4700::6810:94f4",
      "2606:4700::6810:95f4"
    ],
    "cname": null,
    "mx": [
      "mx-west.fbi.gov (pref 20)",
      "mx-east.fbi.gov (pref 10)"
    ],
    "ns": [
      "ns-cloud-e4.googledomains.com.",
      "ns-cloud-e1.googledomains.com.",
      "ns-cloud-e3.googledomains.com.",
      "ns-cloud-e2.googledomains.com."
    ],
    "caa": [
      "0 issue \"amazon.com\"",
      "0 issue \"entrust.net\"",
      "0 issue \"pki.goog\"",
      "0 issue \"sectigo.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"digicert.com\""
    ],
    "spf": [
      "google-site-verification=L8cauHJF4MANoTCkMbrLkAVfHBta28ctva9n1IDekTo",
      "MS=ms39271050",
      "apple-domain-verification=oOspXl6Jvnx9HzLM",
      "625558384-8740534",
      "v=spf1 +mx ip4:153.31.0.0/16 -all",
      "C8WWN4MbK7z5BL4Ivc/DSxEeVsr18DB5/P8GxlM1S3OfCxexrFpFzpY7MBDBoid3h/OxYU+1H0pFrKWhj1j3cw==",
      "google-site-verification=uTH4Vg-Xcc9hTqSdeThbT9UnYvuphObtVSpCEgaGr78",
      "google-site-verification=6UEk-jfg1xPNjz_rQGcRFJOBGxMy1aARDZUTXgSNAqw",
      "ublrZj1CzpSEiwtiRFKDAyiek8hRqkqaTTApxvhwai14i8JqVBOauW4cA06i39H5Lhl3HnALCM/xfTxIPEXEpA==",
      "google-gws-recovery-domain-verification=74752930",
      "kiro-site-verification=31a85f50-8d2b-4be7-9175-d16a469190ee",
      "amazonses: iUbfpGEqhMPlcmJ0aykJZREltK6pWio9wOgRngnJOQE=",
      "_globalsign-domain-verification=xZMJnzdDAgURaBjUZ6qbqWaaYmV5W3sfo3TF8mUxne",
      "adobe-idp-site-verification=101945e35b37c6efd526cf706f04bc9545a02f9cdc58dbf718678c506697d67d"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-feedback@fbi.gov,mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:dmarc-feedback@fbi.gov; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=fbi.gov",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 14 12:18:41 2026 GMT",
    "notAfter": "Dec 13 13:18:21 2026 GMT",
    "san": [
      "fbi.gov",
      "*.fbi.gov"
    ],
    "days_left": 77,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.16.148.244",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "fbi.gov",
      "samesite": "none"
    },
    {
      "domain": "fbi.gov",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.fbi.gov",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://fbi.gov/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 424,
    "notable": [
      "alpha-sifts-staging.apps.dcap.fbi.gov",
      "alpha-sifts.apps.dcap.fbi.gov",
      "api.fbi.gov",
      "api.sos.fbi.gov",
      "avalanche.dv.apps.dcap.fbi.gov",
      "avalanche.va.apps.dcap.fbi.gov",
      "circe.va.apps.dcap.fbi.gov",
      "denali.dv.apps.dcap.fbi.gov",
      "denali.va.apps.dcap.fbi.gov",
      "frost.va.apps.dcap.fbi.gov",
      "gw-tidal.dv.apps.dcap.fbi.gov",
      "gw-user-portal.dv.apps.dcap.fbi.gov",
      "jira.cjis.fbi.gov",
      "jira.ctp-prev.cjis.fbi.gov",
      "lenz.dv.apps.dcap.fbi.gov"
    ],
    "sample": [
      "acts-csdb-ndcac.fbi.gov",
      "acts-ndcac.fbi.gov",
      "adfs-elab.fbi.gov",
      "adfs-ndcac.fbi.gov",
      "admincenter.certauth.fbi.gov",
      "admincenter.certauth.fs1.fbi.gov",
      "admincenter.fact.fbi.gov",
      "alpha-sifts-staging.apps.dcap.fbi.gov",
      "alpha-sifts.apps.dcap.fbi.gov",
      "api.fbi.gov",
      "api.sos.fbi.gov",
      "archives.fbi.gov",
      "artcrimes.fbi.gov",
      "askcalea.fbi.gov",
      "astra.va.fbi.gov",
      "atlas.fbi.gov",
      "atlasbeta.fbi.gov",
      "autodiscover.fbi.gov",
      "autodiscover.ic.fbi.gov",
      "avalanche.dv.apps.dcap.fbi.gov"
    ],
    "dangling": [
      "alpha-sifts-staging.apps.dcap.fbi.gov",
      "alpha-sifts.apps.dcap.fbi.gov",
      "api.sos.fbi.gov"
    ]
  },
  "apex_txt": [
    "google-site-verification=L8cauHJF4MANoTCkMbrLkAVfHBta28ctva9n1IDekTo",
    "apple-domain-verification=oOspXl6Jvnx9HzLM",
    "google-site-verification=uTH4Vg-Xcc9hTqSdeThbT9UnYvuphObtVSpCEgaGr78",
    "google-site-verification=6UEk-jfg1xPNjz_rQGcRFJOBGxMy1aARDZUTXgSNAqw",
    "google-gws-recovery-domain-verification=74752930"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "serial": 179693053827801930733803251185993419711,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/we1/IaIlhAftIps.crl"
      ],
      "subject_dn": "3110300e060355040313076662692e676f76",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531",
      "not_before": "20260914121841",
      "not_after": "20261213131821"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "#",
      "/@@search?",
      "/search?",
      "/*atct_album_view$",
      "/*folder_factories$",
      "/*folder_summary_view$",
      "/*login_form$",
      "/*mail_password_form$",
      "/*search_rss$",
      "/*sendto_form$",
      "/*summary_view$",
      "/*thumbnail_view$",
      "/plonejsi18n$",
      "/*@@castle.cms.querylisting*?",
      "/*interactive*"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.fbi.gov/",
    "http_status": 301,
    "p404_status": 301,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=31536000; includeSubDomains; preload",
    "crl": {
      "url": "http://c.pki.goog/we1/IaIlhAftIps.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "alt_svc": "h3=\":443\"; ma=86400"
  },
  "elapsed_s": 20.1,
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
