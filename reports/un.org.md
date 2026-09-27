# Security Audit Report — un.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://un.org/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | un.org |
| Test date | 2026-09-27 02:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 3, Info: 17)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 17 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 18 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |
| 19 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 20 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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

### 8. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://un.org/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

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
- **Detail:** Apex TXT records with verification/token content: atlassian-sending-domain-verification=b818d67b-c504-4b82-a2ac-fb1ffa5dd99e; ms-domain-verification=a90c74aa-0e09-44e5-aff2-9e0d51862a8a; atlassian-domain-verification=1rY0mwP3xqUqI0Z6SVEdrrPHJ4hquQL28GrmRTVZ6/IZMKDmPs
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but un.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 37 disallow path(s), e.g. /includes/, /misc/, /modules/, /profiles/, /scripts/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 157.150.185.49 carries PTR www.un.org. for un.org.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for un.org, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 17. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The un.org certificate lists an AIA OCSP responder (http://ocsp.globalsign.com/gsgccr46ovtlsca2025) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 18. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to un.org negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

### 19. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of un.org contains wildcard SAN entry(ies) *.un.org; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 20. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of un.org is http://ocsp.globalsign.com/gsgccr46ovtlsca2025; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

## Evidence (raw response observations)

```json
{
  "domain": "un.org",
  "dns": {
    "a": [
      "157.150.185.49",
      "157.150.185.92"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "un-org.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "ns1.un.org.",
      "ns3.un.org.",
      "ns2.un.org."
    ],
    "caa": [],
    "spf": [
      "sendinblue-code:c80931e2ffea8fadc62c1bfb5141f449",
      "rij4mb6stfqk9nqp6db054r4se",
      "amazonses:cq717whOBbl30dhYr9HtG5aBpZfmtVwZ8/8TyeUrXh8=",
      "atlassian-sending-domain-verification=b818d67b-c504-4b82-a2ac-fb1ffa5dd99e",
      "ms-domain-verification=a90c74aa-0e09-44e5-aff2-9e0d51862a8a",
      "00D2E000000pRe2=1TBVK00000000o1",
      "brevo-code:0502b29d26710cfe3a7f5a6713f7b141",
      "atlassian-domain-verification=1rY0mwP3xqUqI0Z6SVEdrrPHJ4hquQL28GrmRTVZ6/IZMKDmPspPa9jE7fXrIYMj",
      "adobe-idp-site-verification=44b9613bd417076c4622079494211a8fb11053a66a37a841db2e2dceccae8485",
      "atlassian-domain-verification=FTWfMaOalWt6nDxqxSGymL9Ey/KoIooB7a1zLsjL5bvuQbXb/CPo6bsrqR2yTU0G",
      "_globalsign-domain-verification=InsBxD8bdOtSqNib2b8QE1vAWRL07fy1C1VP9BHZO1",
      "atlassian-sending-domain-verification=030cf619-e1ff-4c61-b2ff-0b8bf31422e8",
      "56a37f487f3361c43f8c285de2f7f60839ac3a7f1bd37b37353ecd343c995fa2",
      "brevo-code:8016bd7e8b58b2c44d2253f7a674b1f9",
      "xrqyoOBvFUFgFNdafNF3eo+zN4SEGAc+1gcHkfcbobjGa/UFAkMc/rCWUxywPjgWU1yMIYtuFAnHfLXdgFbRLQ==",
      "FOhfWhsJtJ/FZcqQdLjqBNwOqynP/KX4ozWsJFw+k50mDbWjv05zbvEonHMzMIKP9XSZ77kWWuilSHT/t7BQ8w==",
      "j9lgbXbR0aOn/a3/tHAIQ1aK4uhUriBVu4/6I88jmBK0NyrCV36RIyrHwXouU3F0uQSEK0EPj6eBZ/Tc1odW4w==",
      "brevo-code:4258a8aaff2c4cc4d4f46631ee3f416d",
      "d365mktkey=GU4x93TE2dUlhH2NSdB6v7gbxcKnvDje0eF8WD0rNnUx",
      "apple-domain-verification=yaMAnI0GjK2mwjBL",
      "mandrill_verify.J6D4EK4DxGiLqR1nMTfHSA",
      "teamviewer-sso-verification=fde5c90fdb764da199caa79160aef58b",
      "cisco-ci-domain-verification=71023db9cebccd164d6c6916b649179c4109a8bf4a53206db808dc9c778dd271",
      "atlassian-sending-domain-verification=685ec4a1-3cfc-4ffa-8d51-9f6bb6f07baa",
      "brevo-code:2b3f7ca5e298561aaac08baef2898ff7",
      "google-site-verification=dFG8i5QSNlXCckN62lWWTmmj7TEVkVh_G82rHzMPeaE",
      "cisco-ci-domain-verification=3be0a328c387dcfe19bfab64b24e33f04b04e2065771adbc4043b754f65d8392",
      "fastly-domain-delegation-xss3y9gtai43byf7o4ey-00458132-2025-07-09",
      "webexdomainverification.4C675B882DC2B136E053AB06FC0A3F65=6652b0a5-c301-4a9f-8629-d7e156da37b8",
      "_globalsign-domain-verification=upE8q9Q9163O4I3STTC5-_7JD5phBQpi2CMFWRCqom",
      "atlassian-domain-verification=4qBZ2F7TUigBgD7l6Ate/ExncM2HVQU855IzHmcHurVkPVGUU6H2ATvyZFEnnk9N",
      "v=spf1 include:spf.protection.outlook.com include:_netblocks.un.org include:_netblocks2.un.org include:_spf.google.com -all",
      "atlassian-sending-domain-verification=1d232bde-ddc5-4e81-84a4-5fc29c17acdf",
      "iContact1651565",
      "MS=ms26002463"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc@un.org; ruf=mailto:dmarc@un.org; fo=0:1:d:s; adkim=r; aspf=r"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-SHA384",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=United Nations, commonName=*.un.org",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign GCC R46 OV TLS CA 2025",
    "notBefore": "Sep  4 17:41:36 2026 GMT",
    "notAfter": "Mar 22 17:41:36 2027 GMT",
    "san": [
      "*.un.org",
      "un.org"
    ],
    "days_left": 176,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "157.150.185.49",
    "open": []
  },
  "https": {
    "status": 302,
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
      "origin": "https://sub.un.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://un.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "atlassian-sending-domain-verification=b818d67b-c504-4b82-a2ac-fb1ffa5dd99e",
    "ms-domain-verification=a90c74aa-0e09-44e5-aff2-9e0d51862a8a",
    "atlassian-domain-verification=1rY0mwP3xqUqI0Z6SVEdrrPHJ4hquQL28GrmRTVZ6/IZMKDmPs",
    "adobe-idp-site-verification=44b9613bd417076c4622079494211a8fb11053a66a37a841db2e",
    "atlassian-domain-verification=FTWfMaOalWt6nDxqxSGymL9Ey/KoIooB7a1zLsjL5bvuQbXb/C"
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
      "aia_ocsp": "http://ocsp.globalsign.com/gsgccr46ovtlsca2025",
      "serial": 19763309520811260952515083376,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": null,
      "san": [
        "*.un.org",
        "un.org"
      ],
      "subject_dn": "310b30090603550406130255533111300f060355040813084e657720596f726b3111300f060355040713084e657720596f726b31173015060355040a130e556e69746564204e6174696f6e733111300f06035504030c082a2e756e2e6f7267",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312a302806035504031321476c6f62616c5369676e2047434320523436204f5620544c532043412032303235",
      "not_before": "20260904174136",
      "not_after": "20270322174136"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/includes/",
      "/misc/",
      "/modules/",
      "/profiles/",
      "/scripts/",
      "/themes/",
      "/en/internaljustice/files/",
      "/CHANGELOG.txt",
      "/cron.php",
      "/INSTALL.mysql.txt",
      "/INSTALL.pgsql.txt",
      "/INSTALL.sqlite.txt",
      "/install.php",
      "/INSTALL.txt",
      "/LICENSE.txt"
    ]
  },
  "x12": {
    "status": 302,
    "ptr": [
      "www.un.org."
    ]
  },
  "x13": {
    "root_status": 302,
    "root_location": "https://www.un.org/",
    "http_status": 302,
    "p404_status": 302,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 302,
    "hsts": "max-age=31536000; includeSubDomains"
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES256-SHA384",
    "cipher_ver": "TLSv1.2",
    "root_status": 302
  },
  "x16": {
    "root_status": 302
  },
  "x17": {
    "wildcard_san": [
      "*.un.org"
    ],
    "ocsp_http": "http://ocsp.globalsign.com/gsgccr46ovtlsca2025"
  },
  "elapsed_s": 64.5,
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
