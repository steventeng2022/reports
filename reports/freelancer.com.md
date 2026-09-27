# Security Audit Report — freelancer.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://freelancer.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | freelancer.com |
| Test date | 2026-09-27 02:30 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 4, Info: 20)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 16 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 19 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 20 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 21 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 22 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 23 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |
| 24 | info | CT1 | 36 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=2592000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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
- **Detail:** Header reveals: nginx
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

### 13. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (8vk43h0nwem8zs.freelancer.com and 2t3x02alzfzd7p.freelancer.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: twilio-domain-verification=e6bbec233a8c9e43fe0548ee6c530dfe; globalsign-domain-verification=WkLv9MyE6hoZ2g9h5eP3fBXm0FAfqv5X8L-J8iPmGe; anthropic-domain-verification-zmrkrz=BWcvNIhdz7pRP5S3gNSKur2wW
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m01.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but freelancer.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 40 disallow path(s), e.g. /, /, /sellers/placebid.php*, /buyers/repost.php*, /ajax/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 34.197.165.66 carries PTR ec2-34-197-165-66.compute-1.amazonaws.com. for freelancer.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 19. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for freelancer.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 20. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The freelancer.com certificate lists an AIA OCSP responder (http://ocsp.r2m01.amazontrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 21. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of freelancer.com contains wildcard SAN entry(ies) *.freelancer.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 22. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of freelancer.com is http://ocsp.r2m01.amazontrust.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 23. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of freelancer.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

### 24. [INFO] 36 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: git.freelancer.com, my.freelancer.com, news.freelancer.com, www.my.freelancer.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "freelancer.com",
  "dns": {
    "a": [
      "34.197.165.66",
      "54.221.62.44",
      "52.86.196.209"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx4.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 20)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx5.googlemail.com (pref 30)"
    ],
    "ns": [
      "ns-549.awsdns-04.net.",
      "ns-1780.awsdns-30.co.uk.",
      "ns-1363.awsdns-42.org.",
      "ns-470.awsdns-58.com."
    ],
    "caa": [],
    "spf": [
      "twilio-domain-verification=e6bbec233a8c9e43fe0548ee6c530dfe",
      "globalsign-domain-verification=WkLv9MyE6hoZ2g9h5eP3fBXm0FAfqv5X8L-J8iPmGe",
      "ZOOM_verify_MucGMGVCBb0sY18bpTcobR",
      "anthropic-domain-verification-zmrkrz=BWcvNIhdz7pRP5S3gNSKur2wW",
      "MS=ms24738001",
      "v=spf1 include:_spf1.freelancer.com include:_spf2.freelancer.com include:_spf.google.com -all",
      "openai-domain-verification=dv-1ktftOr3h5KrYkHrCX8CxulK",
      "cursor-domain-verification-1c4pg9=RSGYjeGSZhXVJg4djpmBMSxjy",
      "ahrefs-site-verification_d3c10f66e1e45dd0ba44ea9e87972068ada4cc55399000cd0bf2dd68a7338a46"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=100; rua=mailto:y4fb8gcr@ag.au.dmarcian.com,mailto:61597d2f@mxtoolbox.dmarc-report.com,mailto:a68db7279cf8db37fa9c3e812a3543a8-t@dmarc.report-uri.com,mailto:dmarc+rua@freelancer.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=freelancer.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Aug 29 00:00:00 2026 GMT",
    "notAfter": "Mar 14 23:59:59 2027 GMT",
    "san": [
      "freelancer.com",
      "*.freelancer.com"
    ],
    "days_left": 168,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.197.165.66",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.freelancer.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://freelancer.com:443/"
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
    "count": 36,
    "notable": [
      "git.freelancer.com",
      "my.freelancer.com",
      "news.freelancer.com",
      "www.my.freelancer.com"
    ],
    "sample": [
      "accounts.freelancer.com",
      "blue.mcp.freelancer.com",
      "br.freelancer.com",
      "contracts.freelancer.com",
      "cx.freelancer.com",
      "cz.freelancer.com",
      "dk.freelancer.com",
      "fi.freelancer.com",
      "fr.freelancer.com",
      "freelancer.com",
      "git.freelancer.com",
      "green.mcp.freelancer.com",
      "m.arrow.freelancer.com",
      "m.freight.freelancer.com",
      "mcp.freelancer.com",
      "my.freelancer.com",
      "news.freelancer.com",
      "notifications.freelancer.com",
      "phabricator.freelancer.com",
      "pypi.freelancer.com"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "twilio-domain-verification=e6bbec233a8c9e43fe0548ee6c530dfe",
    "globalsign-domain-verification=WkLv9MyE6hoZ2g9h5eP3fBXm0FAfqv5X8L-J8iPmGe",
    "anthropic-domain-verification-zmrkrz=BWcvNIhdz7pRP5S3gNSKur2wW",
    "openai-domain-verification=dv-1ktftOr3h5KrYkHrCX8CxulK",
    "cursor-domain-verification-1c4pg9=RSGYjeGSZhXVJg4djpmBMSxjy"
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
      "serial": 19979168843911046305470777395134173750,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m01.amazontrust.com/r2m01.crl"
      ],
      "san": [
        "freelancer.com",
        "*.freelancer.com"
      ],
      "subject_dn": "311730150603550403130e667265656c616e6365722e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3031",
      "not_before": "20260829000000",
      "not_after": "20270314235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/",
      "/sellers/placebid.php*",
      "/buyers/repost.php*",
      "/ajax/",
      "/users/login-fast.php*",
      "/users/login-faster.php*",
      "/users/login-instant.php*",
      "/users/login-quick.php*",
      "/bl-email/*",
      "/users/onUpdateOnlineStatus.php*",
      "/online-count/*",
      "/report/violation*",
      "/widgets$",
      "/widgets/*"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-34-197-165-66.compute-1.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.freelancer.com/",
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
    "hsts": "max-age=2592000",
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
    "root_status": 301
  },
  "x17": {
    "wildcard_san": [
      "*.freelancer.com"
    ],
    "ocsp_http": "http://ocsp.r2m01.amazontrust.com"
  },
  "elapsed_s": 47.5,
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
