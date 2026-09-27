# Security Audit Report — ifttt.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ifttt.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ifttt.com |
| Test date | 2026-09-27 02:34 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **28** (High: 0, Medium: 0, Low: 0, Info: 28)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 8 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 9 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 10 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 15 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 16 | info | HTML3 | Third-party <iframe> embedded in root document | CWE-643 |
| 17 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 18 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 19 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 20 | info | H25 | server-timing response header exposed | CWE-200 |
| 21 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 22 | info | HTML12 | preconnect/dns-prefetch declares third-party destinations | CWE-200 |
| 23 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 24 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 25 | info | H11 | Legacy Flash cross-domain-policy exposure header | CWE-327 |
| 26 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |
| 27 | info | HTML16 | Inline event handlers in root document | CWE-79 |
| 28 | info | HTML19 | data: URIs present in root document | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

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

### 9. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=LaHtMW5vokuLBZBVhajjw-NS3aQbRMOOz92B-RM_4hQ; stripe-verification=d9aecd16a51b8f74a32c270d11a6bce84470c737c9d1e1de696edbce60ea; google-site-verification=VdD3iT9gG8si3Zu4-crc2cMxN3b3oiRHtFcEAiDwTLc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 10. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but ifttt.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 14 disallow path(s), e.g. /search/query/, /unsubscribe-from-applet/, /unsubscribe, /missing_link, /create/api/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://ifttt.com/ carries Cache-Control: max-age=0, public, s-maxage=41905 (plus ETag/Last-Modified freshness fields); shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.169.121.2 carries PTR server-3-169-121-2.tpe53.r.cloudfront.net. for ifttt.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 15. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on ifttt.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 16. [INFO] Third-party <iframe> embedded in root document (`HTML3`)

- **CWE:** CWE-643
- **Detail:** Root document of ifttt.com embeds 1 cross-origin iframe(s), e.g. https://www.googletagmanager.com/ns.html?id=GTM-NNB6HCT; embedded origins are framed inside the page with its trust context.
- **Recommendation:** Review embedded origins and consider sandbox attributes.

### 17. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on ifttt.com lists 7 <loc> URL(s) across 8 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 18. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of ifttt.com references 11 distinct third-party registrable domains (e.g. w3.org, googletagmanager.com, schema.org, sentry.io, facebook.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 19. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of ifttt.com sends a CSP but contains 6 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 20. [INFO] server-timing response header exposed (`H25`)

- **CWE:** CWE-200
- **Detail:** The root response of ifttt.com sends server-timing (cdn-cache-hit,cdn-pop;desc="TPE53-P1",cdn-rid;desc="lIlJP3ks3ZVTN6Uvi0dSosOSkCc6); server/edge processing metrics are disclosed to any client.
- **Recommendation:** Restrict server-timing to authenticated/debug contexts if the internals are sensitive.

### 21. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on ifttt.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 22. [INFO] preconnect/dns-prefetch declares third-party destinations (`HTML12`)

- **CWE:** CWE-200
- **Detail:** Root document of ifttt.com declares preconnect/dns-prefetch/modulepreload for 1 third-party registrable domain(s) (e.g. googletagmanager.com); declared (not yet loaded) destinations widen the expected network topology of the page.
- **Recommendation:** Review declared third-party destinations as part of the supply-chain inventory.

### 23. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of ifttt.com contains wildcard SAN entry(ies) *.ifttt.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 24. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of ifttt.com is http://ocsp.r2m04.amazontrust.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 25. [INFO] Legacy Flash cross-domain-policy exposure header (`H11`)

- **CWE:** CWE-327
- **Detail:** The root of ifttt.com sends X-Permitted-Cross-Domain-Policies (none); the referenced cross-domain policy files remain fetchable by any origin.
- **Recommendation:** Review the referenced policy files; remove the header if Flash is gone.

### 26. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of ifttt.com discloses a 1-hop fronting chain (1.1 5397f2111d5135af03405b407e5da884.cloudfront.net (CloudFront)); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

### 27. [INFO] Inline event handlers in root document (`HTML16`)

- **CWE:** CWE-79
- **Detail:** The root document of ifttt.com contains 11 inline event handler attribute(s); each is a DOM-level execution point that SRI does not constrain.
- **Recommendation:** Move handlers to external scripts where feasible and keep them covered by CSP.

### 28. [INFO] data: URIs present in root document (`HTML19`)

- **CWE:** CWE-200
- **Detail:** The root document of ifttt.com references 32 data: URI payload(s); inline data resources bypass the normal fetch/CORS path and should be inventoried.
- **Recommendation:** Review inline data payloads (especially scripts/iframes) as part of the asset inventory.

## Evidence (raw response observations)

```json
{
  "domain": "ifttt.com",
  "dns": {
    "a": [
      "3.169.121.2",
      "3.169.121.41",
      "3.169.121.105",
      "3.169.121.27"
    ],
    "aaaa": [
      "2600:9000:284c:d200:1:b1c6:9e40:93a1",
      "2600:9000:284c:1a00:1:b1c6:9e40:93a1",
      "2600:9000:284c:fe00:1:b1c6:9e40:93a1",
      "2600:9000:284c:f200:1:b1c6:9e40:93a1",
      "2600:9000:284c:ea00:1:b1c6:9e40:93a1",
      "2600:9000:284c:a00:1:b1c6:9e40:93a1",
      "2600:9000:284c:2e00:1:b1c6:9e40:93a1",
      "2600:9000:284c:8c00:1:b1c6:9e40:93a1"
    ],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-1614.awsdns-09.co.uk.",
      "ns-425.awsdns-53.com.",
      "ns-1400.awsdns-47.org.",
      "ns-676.awsdns-20.net."
    ],
    "caa": [
      "0 issue \"godaddy.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"digicert.com\"",
      "0 issuewild \"digicert.com\"",
      "0 issuewild \"godaddy.com\"",
      "0 issue \"amazon.com\"",
      "0 issuewild \"globalsign.com\"",
      "0 issue \"globalsign.com\"",
      "0 issuewild \"amazon.com\""
    ],
    "spf": [
      "google-site-verification=LaHtMW5vokuLBZBVhajjw-NS3aQbRMOOz92B-RM_4hQ",
      "edca106a3d3b474e87b5e47c25f607ec",
      "v=spf1 include:sendgrid.net include:_spf.google.com include:customeriomail.com include:mail.zendesk.com include:stspg-customer.com -all",
      "stripe-verification=d9aecd16a51b8f74a32c270d11a6bce84470c737c9d1e1de696edbce60ea7b47",
      "MS=ms71593285",
      "google-site-verification=VdD3iT9gG8si3Zu4-crc2cMxN3b3oiRHtFcEAiDwTLc",
      "v=MCPv1; k=ed25519; p=shhg+Sx/4D+wFvY1jwECmtgaGtpfAC5UDl0mb+mhdNg=",
      "a774vnn3gtgp35cvtd31idrcug",
      "_globalsign-domain-verification=rRjaOlcgFhBuUq2_dp1lnClpS6rvXrnUtycKh8GTEH",
      "hubspot-developer-verification=ODA3YjI3MGQtOTk1Ni00YzgxLWE2NjAtNzkyYjljZDU4MzVj",
      "status-page-domain-verification=btfx82x3lwwg",
      "facebook-domain-verification=2gbh6mjor9buxlzajjq1hjbnksveuo",
      "openai-domain-verification=dv-owUo2sHFljJJv2dyVfHqW3bb",
      "have-i-been-pwned-verification=1931e44ce46fd205b3806eff20a8b416",
      "pinterest-site-verification=8e6e3928621ee8deeaa774c7569bb607",
      "qrql38igvi0ce4abfi3on0vvke",
      "google-site-verification=sdwLeEbGkwDQnNef_ZybsYYO1nz4RksHjJlL4BFy97c",
      "globalsign-domain-verification=2D384BE73AFA22F600E2F2FD71973C63"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:arqctnow@ag.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=ifttt.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Oct 30 00:00:00 2025 GMT",
    "notAfter": "Nov 27 23:59:59 2026 GMT",
    "san": [
      "ifttt.com",
      "*.ifttt.com"
    ],
    "days_left": 61,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.121.2",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Automate. Save time. Get more done. - IFTTT"
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [
    {
      "domain": "ifttt.com",
      "samesite": "lax"
    },
    {
      "domain": "ifttt.com",
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
      "origin": "https://sub.ifttt.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ifttt.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 302,
    "/.htaccess": 404,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=LaHtMW5vokuLBZBVhajjw-NS3aQbRMOOz92B-RM_4hQ",
    "stripe-verification=d9aecd16a51b8f74a32c270d11a6bce84470c737c9d1e1de696edbce60ea",
    "google-site-verification=VdD3iT9gG8si3Zu4-crc2cMxN3b3oiRHtFcEAiDwTLc",
    "_globalsign-domain-verification=rRjaOlcgFhBuUq2_dp1lnClpS6rvXrnUtycKh8GTEH",
    "hubspot-developer-verification=ODA3YjI3MGQtOTk1Ni00YzgxLWE2NjAtNzkyYjljZDU4MzVj"
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
      "aia_ocsp": "http://ocsp.r2m04.amazontrust.com",
      "serial": 12426328962240815014917108860467707641,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "san": [
        "ifttt.com",
        "*.ifttt.com"
      ],
      "subject_dn": "311230100603550403130969667474742e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20251030000000",
      "not_after": "20261127235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/search/query/",
      "/unsubscribe-from-applet/",
      "/unsubscribe",
      "/missing_link",
      "/create/api/",
      "/dri/",
      "/search/query/",
      "/unsubscribe-from-applet/",
      "/unsubscribe",
      "/missing_link",
      "/create/api/",
      "/dri/",
      "/join",
      "/login"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-3-169-121-2.tpe53.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 301,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "stapling": "inconclusive",
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
      "urls": 7,
      "indexes": 8
    },
    "crl": {
      "url": "http://crl.r2m04.amazontrust.com/r2m04.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "x16": {
    "root_status": 200,
    "server_timing": "cdn-cache-hit,cdn-pop;desc=\"TPE53-P1\",cdn-rid;desc=\"lIlJP3ks3ZVTN6Uvi0dSosOSkCc6dThzJDTzEz1vFgZrRtH8fqLCrg==\",cdn-hit-la",
    "cdn": [
      "CloudFront",
      "Fastly"
    ],
    "preconnect": [
      "googletagmanager.com"
    ]
  },
  "x17": {
    "wildcard_san": [
      "*.ifttt.com"
    ],
    "ocsp_http": "http://ocsp.r2m04.amazontrust.com",
    "xcpd": "none",
    "via": "1.1 5397f2111d5135af03405b407e5da884.cloudfront.net (CloudFront)",
    "inline_handlers": 11,
    "data_uris": 32
  },
  "elapsed_s": 10.0,
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
