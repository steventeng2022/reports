# Security Audit Report — amazon.es

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://amazon.es/ |
| Bug bounty program | Amazon |
| Listed scope domain | amazon.es |
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
- **Detail:** Apex TXT records with verification/token content: bluebeam-verification=gqrddudtng5xwjh4zd9wtx8a3m51or; canva-site-verification=SsmajveJ2yhT-JibqBbk6A; google-site-verification=a3r-mlTjHUVRE2712GFvtcHHoCgXwqI_8MWY1DFbtmY
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 190 disallow path(s), e.g. */s?k=*&rh=n*p_*p_*p_, /dp/product-availability/, /dp/rate-this-item/, /exec/obidos/account-access-login, /exec/obidos/change-style
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.253.182.49 carries PTR ec2-3-253-182-49.eu-west-1.compute.amazonaws.com. for amazon.es.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on amazon.es; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 19. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for amazon.es, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 20. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The amazon.es certificate lists an AIA OCSP responder (http://ocsp.r2m04.amazontrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

## Evidence (raw response observations)

```json
{
  "domain": "amazon.es",
  "dns": {
    "a": [
      "3.253.182.49",
      "3.253.168.8",
      "3.254.238.145"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "amazon-smtp.amazon.com (pref 10)"
    ],
    "ns": [
      "ns1.amzndns.com.",
      "ns1.amzndns.org.",
      "ns2.amzndns.com.",
      "ns2.amzndns.org.",
      "ns2.amzndns.co.uk.",
      "ns1.amzndns.co.uk.",
      "ns1.amzndns.net.",
      "ns2.amzndns.net."
    ],
    "caa": [],
    "spf": [
      "bluebeam-verification=gqrddudtng5xwjh4zd9wtx8a3m51or",
      "v=spf1 include:amazon.com -all",
      "canva-site-verification=SsmajveJ2yhT-JibqBbk6A",
      "google-site-verification=a3r-mlTjHUVRE2712GFvtcHHoCgXwqI_8MWY1DFbtmY",
      "sending_domain229492=63325686e4cd99bdb65545f58c7454650c6283ed1c561677ff2e5bdf03c96a44",
      "sending_domain1003771=179232522a19a554e509600d3bc16a732d5e0e3c309f0fb788e2366037a4d763",
      "facebook-domain-verification=ar49zn2kc5dktr4xcum0wwpy9abdoq",
      "MS=ms12730066",
      "google-gws-recovery-domain-verification=68063360",
      "sending_domain608861=32f0b9b0f7cd1a533f2564eceb1b96428940a6e003287c1d09fe70d0b92a89f4",
      "google-site-verification=YMAfjgfgkzIINyWubxb8MSEjzD7hq4Eet5R5t6uPuLs",
      "autodesk-domain-verification=DpHxeICG_MduAndXVeb8",
      "MS=ms34237165",
      "cisco-ci-domain-verification=7b42ea16e70f90dd1d35f1aed713e13f5945131c402198eeadb9b6075ee2b3e4",
      "cisco-ci-domain-verification=62e62968f975ff54a47bdcc4a9de00ea67e9bd8287922baa42fb5c66d15a3124",
      "docker-verification=53562ee7-90ff-4854-b952-1d508197b2c2",
      "spf2.0/pra include:amazon.com -all",
      "TS1760027",
      "sending_domain229492=236b587bfcc126d9624af08947c62ef404f684b38397c40de8905c56c2aedfd5",
      "google-site-verification=hXdp6u6Ea978P7m8xjhPg8cNUix2-l-GloHICzelyQ8",
      "sending_domain608861=f77de0fdda1425c57781454bddb9342f7377c19d8a49a03f17183435660bf5eb",
      "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbDvoGpRaIwj/tgPH",
      "box-domain-verification=ffea95cd0e0d61c302198367155b07e74fd534fa1d867662dc9bf9969b6f535d",
      "google-gws-recovery-domain-verification=70440507",
      "liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo",
      "kahoot-domain-verification=80878754b939ac26c7ec90dd86251f0d6a477d7b7eda9d1adda907572cc75e8d",
      "sending_domain1003771=a40bb77e2438c6639b1d2f078f8489067b7e975cc8f0a96495fd010611250180",
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
    "subject": "commonName=*.bw.peg.a2z.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Aug 23 00:00:00 2026 GMT",
    "notAfter": "Mar  8 23:59:59 2027 GMT",
    "san": [
      "*.bw.peg.a2z.com",
      "amazon.es",
      "p-y3-www-amazon-es-kalias.amazon.es",
      "p-yo-www-amazon-es-kalias.amazon.es",
      "www.amazon.es",
      "edgeflow.aero.1fe6d5bb2-frontier.amazon.es",
      "edgeflow-dp.aero.1fe6d5bb2-frontier.amazon.es",
      "p-nt-www-amazon-es-kalias.amazon.es",
      "origin-www.amazon.es"
    ],
    "days_left": 163,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.253.182.49",
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
      "origin": "https://sub.amazon.es",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://amazon.es/"
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
    "bluebeam-verification=gqrddudtng5xwjh4zd9wtx8a3m51or",
    "canva-site-verification=SsmajveJ2yhT-JibqBbk6A",
    "google-site-verification=a3r-mlTjHUVRE2712GFvtcHHoCgXwqI_8MWY1DFbtmY",
    "facebook-domain-verification=ar49zn2kc5dktr4xcum0wwpy9abdoq",
    "google-gws-recovery-domain-verification=68063360"
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
      "not_before": "20260823000000",
      "not_after": "20270308235959"
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
      "/exec/obidos/dt/assoc/handle-buy-box",
      "/exec/obidos/flex-sign-in",
      "/exec/obidos/handle-buy-box",
      "/exec/obidos/refer-a-friend-login",
      "/exec/obidos/subst/associates/join",
      "/exec/obidos/subst/marketplace/sell-your-collection.html",
      "/exec/obidos/subst/marketplace/sell-your-stuff.html",
      "/exec/obidos/subst/partners/friends/access.html",
      "/exec/obidos/tg/cm/member/",
      "/gp/cart"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-3-253-182-49.eu-west-1.compute.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.amazon.es/",
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
  "elapsed_s": 34.3,
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
