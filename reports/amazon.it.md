# Security Audit Report — amazon.it

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://amazon.it/ |
| Bug bounty program | Amazon |
| Listed scope domain | amazon.it |
| Test date | 2026-09-26 21:57 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 4, Info: 16)

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
| 18 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 19 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 20 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Server
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
- **Detail:** Header reveals: Server
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
- **Detail:** Apex TXT records with verification/token content: bluebeam-verification=j8cz0fqcibcu2o5ifp92okt75zq1qy; docker-verification=8a768a1f-5700-4c2e-a231-7ed92e3f54b0; autodesk-domain-verification=pGlBduQGBF3kHlLs6Zpw
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m01.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 199 disallow path(s), e.g. */s?k=*&rh=n*p_*p_*p_, /dp/product-availability/, /dp/rate-this-item/, /exec/obidos/account-access-login, /exec/obidos/change-style
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.253.170.137 carries PTR ec2-3-253-170-137.eu-west-1.compute.amazonaws.com. for amazon.it.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on amazon.it; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 19. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for amazon.it, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 20. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The amazon.it certificate lists an AIA OCSP responder (http://ocsp.r2m01.amazontrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

## Evidence (raw response observations)

```json
{
  "domain": "amazon.it",
  "dns": {
    "a": [
      "3.253.170.137",
      "3.253.168.26",
      "3.253.168.74"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "amazon-smtp.amazon.com (pref 10)"
    ],
    "ns": [
      "ns2.amzndns.org.",
      "ns2.amzndns.net.",
      "ns2.amzndns.com.",
      "ns2.amzndns.co.uk."
    ],
    "caa": [],
    "spf": [
      "bluebeam-verification=j8cz0fqcibcu2o5ifp92okt75zq1qy",
      "docker-verification=8a768a1f-5700-4c2e-a231-7ed92e3f54b0",
      "autodesk-domain-verification=pGlBduQGBF3kHlLs6Zpw",
      "box-domain-verification=ffea95cd0e0d61c302198367155b07e74fd534fa1d867662dc9bf9969b6f535d",
      "cisco-ci-domain-verification=59a6c2ade22e603cac8d853f80e7f0be82789e89cbb24b41629ae41b3aebd9e9",
      "google-site-verification=Jr6NOP2z_M0VuzOjZ3JQA-odL34DY95dL0NL-R8JY1s",
      "cisco-ci-domain-verification=645d5ac7db684898baae8490f752160375fd2ec85fc7554f5b42709d2ec6cfc9",
      "TS1760027",
      "stripe-verification=8E217BE0FF12B50596BD78EEA3F81E62C6C7A2AC78FBD46DAD95B7D21BA2F8BF",
      "kahoot-domain-verification=22ee64d0aec326366c08cdfa7197de5c3886fe27cceb8640d7d5588625c9f0b4",
      "google-gws-recovery-domain-verification=69891840",
      "sending_domain229492=2e0c5055ba36638c1cd1353ccbc8078198131db60d2df6e2cbdeaf1d539504a5",
      "MS=ms49381604",
      "sending_domain608861=f5058b910003ca4502b4614ae3d28c6a6d27ee085235ed0153ff24721fd96b2c",
      "sending_domain608861=5681d4120436c25f201e7d33a99f548f84376ffbb0925dca0aee11e02986afd4",
      "sending_domain229492=773318fa1b5a7192d6972d94e73086484013af73e1fedb4a97c271d8c249de23",
      "google-site-verification=KvROSuvY2SUsytarO3DcfIyxVhaxKvpet9PWY7ffrqI",
      "google-site-verification=EAue0f6D-B6SRexlTvlXOLQmyUisWC6erRZcz9PzCxU",
      "google-site-verification=gSzwNH1ysDvam__XXTSyD7tRg77gcKvjZdcAWWPx7Yk",
      "spf2.0/pra include:amazon.com -all",
      "facebook-domain-verification=y6vg4mpjcry0iwvtyvsgi97pmmhgu9",
      "MS=ms46535533",
      "v=spf1 include:amazon.com -all",
      "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbDvoGpRaIwj/tgPH",
      "sending_domain1003771=8bc848545d7604d033f93cce2a469b0ad06838e3988942c5fc49bfb3b76034a8",
      "canva-site-verification=yTqsBFJlSq5ffci9yBLAOQ",
      "liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo",
      "sending_domain1003771=b2348ea31ce95947027cc796d3e0f4e42aeb38824709846b24c77bd6960b5516",
      "adobe-idp-site-verification=b6bcd3e5aaffc63607c8bf75744d9a0d1febc50dd7f389428e2ae476c9ba8814"
    ],
    "dmarc": [
      "v=DMARC1;",
      "p=quarantine;",
      "pct=100;",
      "rua=mailto:report@dmarc.amazon.com;",
      "ruf=mailto:report@dmarc.amazon.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.cw.peg.a2z.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Aug  9 00:00:00 2026 GMT",
    "notAfter": "Feb 22 23:59:59 2027 GMT",
    "san": [
      "*.cw.peg.a2z.com",
      "origin-www.amazon.it",
      "edgeflow.aero.6ca7af544-frontier.amazon.it",
      "www.amazon.it",
      "edgeflow-dp.aero.6ca7af544-frontier.amazon.it",
      "p-yo-www-amazon-it-kalias.amazon.it",
      "amazon.it",
      "p-y3-www-amazon-it-kalias.amazon.it",
      "p-nt-www-amazon-it-kalias.amazon.it"
    ],
    "days_left": 149,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.253.170.137",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Server"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.amazon.it",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://amazon.it/"
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
    "bluebeam-verification=j8cz0fqcibcu2o5ifp92okt75zq1qy",
    "docker-verification=8a768a1f-5700-4c2e-a231-7ed92e3f54b0",
    "autodesk-domain-verification=pGlBduQGBF3kHlLs6Zpw",
    "box-domain-verification=ffea95cd0e0d61c302198367155b07e74fd534fa1d867662dc9bf996",
    "cisco-ci-domain-verification=59a6c2ade22e603cac8d853f80e7f0be82789e89cbb24b41629"
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
      "not_before": "20260809000000",
      "not_after": "20270222235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "*/s?k=*&rh=n*p_*p_*p_",
      "/dp/product-availability/",
      "/dp/rate-this-item/",
      "/exec/obidos/account-access-login",
      "/exec/obidos/change-style",
      "/exec/obidos/di",
      "/exec/obidos/dt",
      "/exec/obidos/dt/assoc/handle-buy-box",
      "/exec/obidos/flex-sign-in",
      "/exec/obidos/handle-buy-box",
      "/exec/obidos/refer-a-friend-login",
      "/exec/obidos/subst/associates/join",
      "/exec/obidos/subst/marketplace/sell-your-collection.html",
      "/exec/obidos/subst/marketplace/sell-your-stuff.html",
      "/exec/obidos/subst/partners/friends/access.html"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-3-253-170-137.eu-west-1.compute.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.amazon.it/",
    "http_status": 301,
    "p404_status": 301,
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
  "elapsed_s": 35.0,
  "rechecked": "2026-09-26 21:56 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- Findings are reported against the public program scope; submission through the program tracker is pending.
