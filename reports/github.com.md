# Security Audit Report — github.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://github.com/ |
| Bug bounty program | GitHub |
| Listed scope domain | github.com |
| Test date | 2026-09-27 02:31 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 2, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT22 | SSH reachable | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 12 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 13 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 14 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 15 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 16 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 17 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 18 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 19 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 20 | info | HTML12 | preconnect/dns-prefetch declares third-party destinations | CWE-200 |
| 21 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] SSH reachable (`PRT22`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 20.27.177.113:22 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: github.com
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: github.com
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 8. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 9. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: shopify-verification-code=t1YPwcmvnxZyBycaCpk1MPyWoFs72o; krisp-domain-verification=ZlyiK7XLhnaoUQb2hpak1PLY7dFkl1WE; loom-site-verification=f3787154f1154b7880e720a511ea664d
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 241 disallow path(s), e.g. /*/*/pulse, /*/*/projects, /*/*/forks, /*/*/issues/new, /*/*/milestones/new
- **Recommendation:** Review disallowed paths; robots is not access control.

### 12. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of github.com permits unsafe-inline; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 13. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://github.com/ carries Cache-Control: max-age=0, private, must-revalidate (plus ETag/Last-Modified freshness fields); shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 14. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on github.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 15. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The github.com certificate lists an AIA OCSP responder (http://ocsp.sectigo.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 16. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of github.com loads 8 cross-origin script(s) without an integrity attribute, e.g. https://github.githubassets.com/assets/high-contrast-cookie-e3d808ee18eb9784.js, https://github.githubassets.com/assets/environment-a3b33b022e640cb5.js, https://github.githubassets.com/assets/github-elements-f3d3090f1f0c97b2.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 17. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on github.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 18. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of github.com references 6 distinct third-party registrable domains (e.g. githubassets.com, githubusercontent.com, ctfassets.net, github.blog, amazonaws.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 19. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of github.com sends a CSP but contains 6 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 20. [INFO] preconnect/dns-prefetch declares third-party destinations (`HTML12`)

- **CWE:** CWE-200
- **Detail:** Root document of github.com declares preconnect/dns-prefetch/modulepreload for 3 third-party registrable domain(s) (e.g. amazonaws.com, githubassets.com, githubusercontent.com); declared (not yet loaded) destinations widen the expected network topology of the page.
- **Recommendation:** Review declared third-party destinations as part of the supply-chain inventory.

### 21. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of github.com is http://ocsp.sectigo.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

## Evidence (raw response observations)

```json
{
  "domain": "github.com",
  "dns": {
    "a": [
      "20.27.177.113"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "github-com.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "ns-421.awsdns-52.com.",
      "ns-1707.awsdns-21.co.uk.",
      "dns3.p08.nsone.net.",
      "dns1.p08.nsone.net.",
      "dns4.p08.nsone.net.",
      "dns2.p08.nsone.net.",
      "ns-520.awsdns-01.net.",
      "ns-1283.awsdns-32.org."
    ],
    "caa": [
      "0 issuewild \"letsencrypt.org\"",
      "0 issuewild \"digicert.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"digicert.com\"",
      "0 issuewild \"sectigo.com\"",
      "0 issue \"sectigo.com\"",
      "0 issue \"globalsign.com\""
    ],
    "spf": [
      "v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.2",
      "27.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all",
      "00Dd0000000hHE0=1TBKg000000TN2r",
      "shopify-verification-code=t1YPwcmvnxZyBycaCpk1MPyWoFs72o",
      "krisp-domain-verification=ZlyiK7XLhnaoUQb2hpak1PLY7dFkl1WE",
      "loom-site-verification=f3787154f1154b7880e720a511ea664d",
      "stripe-verification=f88ef17321660a01bab1660454192e014defa29ba7b8de9633c69d6b4912217f",
      "calendly-site-verification=at0DQARi7IZvJtXQAWhMqpmIzpvoBNF7aam5VKKxP",
      "google-site-verification=UTM-3akMgubp6tQtgEuAkYNYLyYAvpTnnSrDMWoDR3o",
      "cursor-domain-verification-gtfwmt=1rfLOtiTngX5QSxD5HvNKTvm3",
      "facebook-domain-verification=39xu4jzl7roi7x0n93ldkxjiaarx50",
      "MS=ms58704441",
      "MS=ms44452932",
      "adobe-idp-site-verification=b92c9e999aef825edc36e0a3d847d2dbad5b2fc0e05c79ddd7a16139b48ecf4b",
      "anthropic-domain-verification-4az7qn=if8YWuRRqwLycGJDooumzHtxm",
      "jamf-site-verification=XtaPNIYghF_e_xRDI8CjgQ",
      "docusign=087098e3-3d46-47b7-9b4e-8a23028154cd",
      "atlassian-domain-verification=jjgw98AKv2aeoYFxiL/VFaoyPkn3undEssTRuMg6C/3Fp/iqhkV4HVV7WjYlVeF8",
      "apple-domain-verification=RyQhdzTl6Z6x8ZP4",
      "MS=6BF03E6AF5CB689E315FB6199603BABF2C88D805",
      "TAILSCALE-xOzoDvFUzZr5YYVCQFuD",
      "google-site-verification=82Le34Flgtd15ojYhHlGF_6g72muSjamlMVThBOJpks",
      "miro-verification=d2e174fdb00c71e0bcf58f8e58c3da2dd80dcfa9",
      "serval-domain-verification-ydryhj=qbkiEakpwEpTvHh5fIiCqtaue",
      "openai-domain-verification=dv-3nh33eQwdkotMIAzLrIDVZo1"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@github.com; ruf=mailto:dmarc@github.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=github.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA DV E36",
    "notBefore": "Sep  1 00:00:00 2026 GMT",
    "notAfter": "Nov 29 23:59:59 2026 GMT",
    "san": [
      "github.com",
      "www.github.com"
    ],
    "days_left": 63,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "20.27.177.113",
    "open": [
      22
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "GitHub · Change is constant. GitHub keeps you ahead. · GitHub"
  },
  "mixed_content": [],
  "tech": [
    "Server: github.com"
  ],
  "cookies": [
    {
      "samesite": "lax"
    },
    {
      "domain": ".github.com",
      "samesite": "lax"
    },
    {
      "domain": ".github.com",
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.github.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://github.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 406,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 406,
    "/phpmyadmin/index.php": 404,
    "/server-status": 200,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "shopify-verification-code=t1YPwcmvnxZyBycaCpk1MPyWoFs72o",
    "krisp-domain-verification=ZlyiK7XLhnaoUQb2hpak1PLY7dFkl1WE",
    "loom-site-verification=f3787154f1154b7880e720a511ea664d",
    "stripe-verification=f88ef17321660a01bab1660454192e014defa29ba7b8de9633c69d6b4912",
    "calendly-site-verification=at0DQARi7IZvJtXQAWhMqpmIzpvoBNF7aam5VKKxP"
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
      "aia_ocsp": "http://ocsp.sectigo.com",
      "serial": 220146849970436463178178372053574587708,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": null,
      "san": [
        "github.com",
        "www.github.com"
      ],
      "subject_dn": "311330110603550403130a6769746875622e636f6d",
      "issuer_dn": "310b300906035504061302474231183016060355040a130f5365637469676f204c696d69746564313730350603550403132e5365637469676f205075626c6963205365727665722041757468656e7469636174696f6e20434120445620453336",
      "not_before": "20260901000000",
      "not_after": "20261129235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/*/*/pulse",
      "/*/*/projects",
      "/*/*/forks",
      "/*/*/issues/new",
      "/*/*/milestones/new",
      "/*/*/issues/search",
      "/*/*/commits/",
      "/*/*/branches",
      "/*/*/contributors",
      "/*/*/tags",
      "/*/*/stargazers",
      "/*/*/watchers",
      "/*/*/network",
      "/*/*/graphs",
      "/*/*/compare"
    ]
  },
  "x12": {
    "status": 200
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
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
    "root_status": 200,
    "hsts": "max-age=31536000; includeSubdomains; preload",
    "security_txt": "/.well-known/security.txt"
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "x16": {
    "root_status": 200,
    "preconnect": [
      "amazonaws.com",
      "githubassets.com",
      "githubusercontent.com"
    ]
  },
  "x17": {
    "ocsp_http": "http://ocsp.sectigo.com"
  },
  "elapsed_s": 20.6,
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
