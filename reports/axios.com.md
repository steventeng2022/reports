# Security Audit Report — axios.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://axios.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | axios.com |
| Test date | 2026-09-27 02:19 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **23** (High: 0, Medium: 0, Low: 4, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 20 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 21 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 22 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 23 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AmazonS3
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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
- **Detail:** Header reveals: AmazonS3
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=AhXdxJp_UuyXXLHEGPfCKtc1gQUSzkanEs-sp5doMYM; workos-domain-verification=6d3515c05c92b333b09d7e47b33d0ac9b02f43c0; google-site-verification=cU32NjH-mhlCih6kUT_FxtE-8hSSu2AU0GgWaRZru10
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m01.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 18 disallow path(s), e.g. Crawl-delay:, /core/*, /admin/, /login/, /sso/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 65.9.180.81 carries PTR server-65-9-180-81.tpe53.r.cloudfront.net. for axios.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for axios.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on axios.com lists 1975 <loc> URL(s) across 1976 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 20. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on axios.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 21. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of axios.com contains wildcard SAN entry(ies) *.axios.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 22. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of axios.com is http://ocsp.r2m01.amazontrust.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 23. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of axios.com discloses a 1-hop fronting chain (1.1 98356305f9e9512175b34bae946e4112.cloudfront.net (CloudFront)); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

## Evidence (raw response observations)

```json
{
  "domain": "axios.com",
  "dns": {
    "a": [
      "65.9.180.81",
      "65.9.180.58",
      "65.9.180.75",
      "65.9.180.89"
    ],
    "aaaa": [
      "2600:9000:202b:c200:f:2743:2840:93a1",
      "2600:9000:202b:a00:f:2743:2840:93a1",
      "2600:9000:202b:e200:f:2743:2840:93a1",
      "2600:9000:202b:ba00:f:2743:2840:93a1",
      "2600:9000:202b:cc00:f:2743:2840:93a1",
      "2600:9000:202b:6800:f:2743:2840:93a1",
      "2600:9000:202b:ca00:f:2743:2840:93a1",
      "2600:9000:202b:1600:f:2743:2840:93a1"
    ],
    "cname": null,
    "mx": [
      "mx0b-0094cb01.pphosted.com (pref 10)",
      "mx0a-0094cb01.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-1914.awsdns-47.co.uk.",
      "ns-1046.awsdns-02.org.",
      "ns-574.awsdns-07.net.",
      "ns-371.awsdns-46.com."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=AhXdxJp_UuyXXLHEGPfCKtc1gQUSzkanEs-sp5doMYM",
      "workos-domain-verification=6d3515c05c92b333b09d7e47b33d0ac9b02f43c0",
      "google-site-verification=cU32NjH-mhlCih6kUT_FxtE-8hSSu2AU0GgWaRZru10",
      "notion-domain-verification=euREWZzi1ay2RZzjh95AYeUhyC0orensMYdbalqiK0u",
      "openai-domain-verification=dv-8hFUJIqySd7Qj0wKcM6V3JqO",
      "google-site-verification=rVBBudGjr06-RdP4hdMECOpyZxxtsMIYWh0F_muCbz0",
      "yahoo-verification-key=LMvH3HEBPuxPkUWPAUSuPR8Y1FxNi29RLlPYS7cXRgE=",
      "v=spf1 mx ip4:148.163.141.127 ip4:148.163.144.231 include:aspmx.sailthru.com include:21431559.spf08.hubspotemail.net include:mail.zendesk.com include:_spf.intacct.com include:_spf.google.com include:amazonses.com ~all",
      "intacct-esk=AE5D6E42C93120C4E0539A220D0AAEF4",
      "google-site-verification=eyfxkl6Nk5RLnsdKs4nVG5NWlTvsoV1k4P1a5813kE8",
      "facebook-domain-verification=huo9d19y5ulzyuyf8qpz5enviugudc",
      "google-site-verification=aGCtHXCTJynR-oEfrgHDaZu6u_h7gKgvVJTB9GxE6dA",
      "airtable-verification=91dae1bbcaba098bd8a59cca3cb449e5",
      "google-site-verification=BXVI1XyBKoyx3gLiz2yE4k42f9gSxPDqVfrKpe9jZF0",
      "google-site-verification=sxCitajaDL8APfsSBq-9_Mv-a5HyzOVDNPzxiyDa2TE",
      "notion-domain-verification=iAHG3rLseOREzVi7Mc6qRexAIjCOld7OIr9zqsMZ4XM",
      "ZOOM_verify_DS99OxYPRV-NzcpHlFlDQw",
      "notion-domain-verification=EKCjbDjkuQgAXTliSNzXLLGQxeGvBFK0lHTztOF1C50",
      "google-site-verification=Dnh_-eZqrPCcaREkSMPt0eUWEgV3MeInwIoqo-TPfXk",
      "facebook-domain-verification=ecd6yhq9up6c8aur88ljizubven1r4",
      "wiz-domain-verification=6abe1e5a4a8d9ce5647fb0fb0dcd285ec989f949e25e49dc1b73e5366d31436d",
      "google-site-verification=V7Mcik3pFDxExCOR0C4-9LD7SVWVT6TPCgW0HfV3z-4",
      "apple-domain-verification=2rkQCIykLAvBOnmf",
      "segment-site-verification=b48CGQ5xBsjOaNRCcp6WwfVvr6n6DrIh",
      "google-site-verification=DM5oCPuErsG4_LXcpFD1d14c6UbZA1YafXgTDzUN8OM",
      "answer=sk4me2e6p3ekdwbx",
      "MS=ms37063808",
      "hubspot-domain-verification=ZDc2MTk0MDQtYjc0Yi00MDUyLTkwNDktZmQzMTM5YTUzNjA4",
      "docusign=b17368bd-d777-4a74-9875-476c5bfe7f45",
      "facebook-domain-verification=be36gv8drf2bak9hawiaylq1ass01x",
      "stripe-verification=C1DE32D201A94B84EA7FD48CEE280A6BCEFD59DBBAAE4A4A6E84D43D01A5631A",
      "google-site-verification=lz4y4j9j_uogKoLYUhIB9UT09dITRaZ_M6R7iks7fHI",
      "google-site-verification=Fz1OOFOio7VO8IiEYEil9ju8RLIcgLW_q67TGxzijmU"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;pct=100;rua=mailto:6cf313c7a0@rua.easydmarc.us;ruf=mailto:6cf313c7a0@ruf.easydmarc.us;ri=86400;fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=axios.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "May 27 00:00:00 2026 GMT",
    "notAfter": "Dec 10 23:59:59 2026 GMT",
    "san": [
      "axios.com",
      "*.axios.com"
    ],
    "days_left": 74,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "65.9.180.81",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
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
      "origin": "https://sub.axios.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://axios.com/"
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
    "google-site-verification=AhXdxJp_UuyXXLHEGPfCKtc1gQUSzkanEs-sp5doMYM",
    "workos-domain-verification=6d3515c05c92b333b09d7e47b33d0ac9b02f43c0",
    "google-site-verification=cU32NjH-mhlCih6kUT_FxtE-8hSSu2AU0GgWaRZru10",
    "notion-domain-verification=euREWZzi1ay2RZzjh95AYeUhyC0orensMYdbalqiK0u",
    "openai-domain-verification=dv-8hFUJIqySd7Qj0wKcM6V3JqO"
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
      "serial": 11159028457654297534569495895137112033,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m01.amazontrust.com/r2m01.crl"
      ],
      "san": [
        "axios.com",
        "*.axios.com"
      ],
      "subject_dn": "31123010060355040313096178696f732e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3031",
      "not_before": "20260527000000",
      "not_after": "20261210235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "Crawl-delay:",
      "/core/*",
      "/admin/",
      "/login/",
      "/sso/",
      "/api/",
      "/core/*",
      "/admin/",
      "/login/",
      "/sso/",
      "/api/",
      "/",
      "/",
      "/",
      "/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "server-65-9-180-81.tpe53.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.axios.com/",
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
      "urls": 1975,
      "indexes": 1976
    },
    "crl": {
      "url": "http://crl.r2m01.amazontrust.com/r2m01.crl",
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
      "CloudFront",
      "Fastly"
    ]
  },
  "x17": {
    "wildcard_san": [
      "*.axios.com"
    ],
    "ocsp_http": "http://ocsp.r2m01.amazontrust.com",
    "via": "1.1 98356305f9e9512175b34bae946e4112.cloudfront.net (CloudFront)"
  },
  "elapsed_s": 8.0,
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
