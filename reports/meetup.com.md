# Security Audit Report — meetup.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://meetup.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | meetup.com |
| Test date | 2026-09-27 02:37 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 3, Info: 17)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
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
| 14 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 15 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 16 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 17 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |
| 18 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 19 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 20 | info | CT1 | 55 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |

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

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

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
- **Detail:** Two random labels (4f89hsjllmeymd.meetup.com and h9kd1pbw0xbyrj.meetup.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=LzTshnYHTmh-qKj8qWTYVNo408Av35GqfZQxSopIWEo; google-site-verification=sc2QcwRmidYh2YB2ghH7c9-GgAZQu0QMtcFrUURtSJQ; google-site-verification=-YC-JRzsddf4MU6k9PhCUBV78tg9R3zqO8WWK7i1SHA
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2025q4 -> http-400
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but meetup.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 116 disallow path(s), e.g. /files/, /fb/, /preview/, /n/*, */calendar/*atom*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of meetup.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 15. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on meetup.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 16. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The meetup.com certificate lists an AIA OCSP responder (http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2025q4) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 17. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to meetup.com negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

### 18. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on meetup.com identify the edge as Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 19. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of meetup.com is http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2025q4; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 20. [INFO] 55 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.meetup.com, api.int.dev.meetup.com, api.int.meetup.com, api.meetup.com, auth.blt.meetup.com, dev.m2mpay.meetup.com, dev.memberpay.meetup.com, help.meetup.com, redash.cloud.dev.meetup.com, test.dev.meetup.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "meetup.com",
  "dns": {
    "a": [
      "151.101.2.217",
      "151.101.194.217",
      "151.101.66.217",
      "151.101.130.217"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 1)"
    ],
    "ns": [
      "ns-919.awsdns-50.net.",
      "ns-40.awsdns-05.com.",
      "ns-1378.awsdns-44.org.",
      "ns-1782.awsdns-30.co.uk."
    ],
    "caa": [
      "0 issuewild \"pki.goog\"",
      "0 issuewild \"certainly.com\"",
      "0 issue \"awstrust.com\"",
      "0 issuewild \"amazon.com\"",
      "0 issuewild \"amazonaws.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"pki.goog\"",
      "0 issue \"certainly.com\"",
      "0 issuewild \"awstrust.com\"",
      "0 issuewild \"letsencrypt.org\"",
      "0 issue \"amazon.com\"",
      "0 issue \"amazonaws.com\"",
      "0 issue \"globalsign.com\"",
      "0 issue \"amazontrust.com\"",
      "0 issuewild \"amazontrust.com\"",
      "0 issuewild \"globalsign.com\""
    ],
    "spf": [
      "_gh-bending-spoons-e=da6293536f",
      "google-site-verification=LzTshnYHTmh-qKj8qWTYVNo408Av35GqfZQxSopIWEo",
      "google-site-verification=sc2QcwRmidYh2YB2ghH7c9-GgAZQu0QMtcFrUURtSJQ",
      "google-site-verification=-YC-JRzsddf4MU6k9PhCUBV78tg9R3zqO8WWK7i1SHA",
      "_gvhn8tc5d0bjvpfjwr6izofm3rw1rzm",
      "google-site-verification=892t2MaS4SZsb48SSg1A3ABMz3RTC_BD0aedsHeQcPs",
      "docusign=0a856615-3cca-4967-af2e-aa849ca42de2",
      "google-site-verification=JU1AoGj_pC_wB0Jxu62NnaIktGqrX8wTvBo9i8XRwHw",
      "google-site-verification=UHCBNwoUShRSmjmm8U3HWmmtbqIV7dsuHyMrhUDOCtQ",
      "v=spf1 include:mail.zendesk.com include:_spf.google.com include:_spf.sparkpostmail.com ~all",
      "facebook-domain-verification=rgyjx6tabxhbz0vs8jznk3h7kw9igq",
      "_globalsign-domain-verification=hnJMGmZ5nxkDzoVy5--BmuTT2DIF9hm5OQ87d_jorS",
      "google-site-verification=d7aAADk1yxzIsb2QOmZY6COjV2y0iPhwwSmmNpJgEfM",
      "rippling-domain-verification=217697edd61756fc"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.bendingspoons.com; sp=reject;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=meetup.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2025 Q4",
    "notBefore": "Dec  9 17:39:12 2025 GMT",
    "notAfter": "Jan 10 17:39:11 2027 GMT",
    "san": [
      "meetup.com"
    ],
    "days_left": 105,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "151.101.2.217",
    "open": []
  },
  "https": {
    "status": 308,
    "content_type": "",
    "title": ""
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
      "origin": "https://sub.meetup.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://meetup.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 308",
    "/redirect?next=https://evil-auditor.example/x -> 308",
    "/go?url=https://evil-auditor.example/x -> 308",
    "/url?url=https://evil-auditor.example/x -> 308"
  ],
  "paths": {
    "/robots.txt": 308,
    "/sitemap.xml": 308,
    "/.well-known/security.txt": 308,
    "/security.txt": 308,
    "/.git/HEAD": 308,
    "/.git/config": 308,
    "/.env": 403,
    "/.htaccess": 308,
    "/wp-login.php": 308,
    "/phpmyadmin/index.php": 308,
    "/server-status": 308,
    "/api/": 308
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 55,
    "notable": [
      "admin.meetup.com",
      "api.int.dev.meetup.com",
      "api.int.meetup.com",
      "api.meetup.com",
      "auth.blt.meetup.com",
      "dev.m2mpay.meetup.com",
      "dev.memberpay.meetup.com",
      "help.meetup.com",
      "redash.cloud.dev.meetup.com",
      "test.dev.meetup.com"
    ],
    "sample": [
      "admin.meetup.com",
      "airflow.blt.meetup.com",
      "analytics-tracking.meetup.com",
      "api.int.dev.meetup.com",
      "api.int.meetup.com",
      "api.meetup.com",
      "auth.blt.meetup.com",
      "bamboo.blt.meetup.com",
      "bazel-cache.blt.meetup.com",
      "blt.meetup.com",
      "campaign-generator.meetup.com",
      "clicks.meetup.com",
      "console.meetup.com",
      "dbhsejcg.meetup.com",
      "dev.m2mpay.meetup.com",
      "dev.memberpay.meetup.com",
      "dp-event-search-edge.meetup.com",
      "dummy.blt.meetup.com",
      "email-analytics.meetup.com",
      "experiences.meetup.com"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=LzTshnYHTmh-qKj8qWTYVNo408Av35GqfZQxSopIWEo",
    "google-site-verification=sc2QcwRmidYh2YB2ghH7c9-GgAZQu0QMtcFrUURtSJQ",
    "google-site-verification=-YC-JRzsddf4MU6k9PhCUBV78tg9R3zqO8WWK7i1SHA",
    "google-site-verification=892t2MaS4SZsb48SSg1A3ABMz3RTC_BD0aedsHeQcPs",
    "google-site-verification=JU1AoGj_pC_wB0Jxu62NnaIktGqrX8wTvBo9i8XRwHw"
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
      "aia_ocsp": "http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2025q4",
      "serial": 1458616425176394435313108830761130764,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.globalsign.com/ca/gsatlasr3dvtlsca2025q4.crl"
      ],
      "san": [
        "meetup.com"
      ],
      "subject_dn": "3113301106035504030c0a6d65657475702e636f6d",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312e302c06035504031325476c6f62616c5369676e2041746c617320523320445620544c532043412032303235205134",
      "not_before": "20251209173912",
      "not_after": "20270110173911"
    },
    "ocsp": "http-400"
  },
  "http2": {
    "robots_disallow": [
      "/files/",
      "/fb/",
      "/preview/",
      "/n/*",
      "*/calendar/*atom*",
      "*/calendar/*rss*",
      "*/calendar/*xml*",
      "*/events/atom/*",
      "*/events/rss/*",
      "*/events/xml/*",
      "*/rsvps/*atom*",
      "*/rsvps/*rss*",
      "*/rsvps/*xml*",
      "*/newest/*atom*",
      "*/newest/*rss*"
    ]
  },
  "x12": {
    "status": 308
  },
  "x13": {
    "root_status": 308,
    "root_location": "https://www.meetup.com/",
    "http_status": 301,
    "p404_status": 308,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 308,
    "hsts": "max-age=7776000",
    "crl": {
      "url": "http://crl.globalsign.com/ca/gsatlasr3dvtlsca2025q4.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "cipher_ver": "TLSv1.2",
    "root_status": 308
  },
  "x16": {
    "root_status": 308,
    "cdn": [
      "Fastly"
    ]
  },
  "x17": {
    "ocsp_http": "http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2025q4"
  },
  "elapsed_s": 47.0,
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
