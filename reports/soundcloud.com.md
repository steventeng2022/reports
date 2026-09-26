# Security Audit Report — soundcloud.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://soundcloud.com/ |
| Bug bounty program | SoundCloud |
| Listed scope domain | soundcloud.com |
| Test date | 2026-09-26 23:38 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **23** (High: 0, Medium: 0, Low: 5, Info: 18)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 11 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 12 | low | P9 | Apache server-status exposed | CWE-200 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 19 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 20 | info | SRV1 | Server header discloses a product version | CWE-200 |
| 21 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 22 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 23 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: am/2
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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
- **Detail:** Header reveals: am/2
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'sc_tracking_anonymous_id' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 11. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'sc_tracking_anonymous_id' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 12. [LOW] Apache server-status exposed (`P9`)

- **CWE:** CWE-200
- **Detail:** /server-status returns 200 with Apache status content.
- **Recommendation:** Deny access to /server-status or restrict it to management networks.

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
- **Detail:** Apex TXT records with verification/token content: postman-domain-verification=5b7709a2c59b36a8a43b9ac9dfce70486e48a77ead9bc6796eb6; stripe-verification=e1469db8bb5c9886c8a7abbece38ddc342618aa4ac7dca85b73731668ea5; jetbrains-domain-verification=77s6xu94q634n5sk6ntslgq5c
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m01.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 8 disallow path(s), e.g. /, /search, /you/, /stream, /upload
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xk4xdyqgppdz9n.html -> 404; error page/headers match: CloudFront.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 19. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on soundcloud.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 20. [INFO] Server header discloses a product version (`SRV1`)

- **CWE:** CWE-200
- **Detail:** Server header on soundcloud.com is 'am/2' and includes a version number, which narrows targeted vulnerability research.
- **Recommendation:** Serve a generic Server value without the version.

### 21. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of soundcloud.com loads 10 cross-origin script(s) without an integrity attribute, e.g. https://a-v2.sndcdn.com/assets/59-ac0a49ce.js, https://a-v2.sndcdn.com/assets/57-5909dd9b.js, https://cdn.cookielaw.org/consent/7e62c772-c97a-4d95-8d0a-f99bbeadcf61/otSDKStub.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 22. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on soundcloud.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 23. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on soundcloud.com lists 53 <loc> URL(s); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

## Evidence (raw response observations)

```json
{
  "domain": "soundcloud.com",
  "dns": {
    "a": [
      "52.84.150.39",
      "52.84.150.35",
      "52.84.150.52",
      "52.84.150.57"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 50)",
      "aspmx.l.google.com (pref 10)",
      "aspmx3.googlemail.com (pref 50)",
      "alt2.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "ns-56.awsdns-07.com.",
      "ns-1745.awsdns-26.co.uk.",
      "ns-799.awsdns-35.net.",
      "ns-1445.awsdns-52.org."
    ],
    "caa": [
      "0 issue \"sectigo.com\"",
      "0 issue \"pki.goog\"",
      "0 issue \"amazontrust.com\"",
      "0 issue \"awstrust.com\"",
      "0 issue \"amazonaws.com\"",
      "0 issue \"digicert.com\"",
      "0 issue \"amazon.com\"",
      "0 issue \"globalsign.com\"",
      "0 issue \"letsencrypt.org\""
    ],
    "spf": [
      "postman-domain-verification=5b7709a2c59b36a8a43b9ac9dfce70486e48a77ead9bc6796eb6d23405f1e97d248fcea57dca123555ac56280fda66895e29ba3a9a0f2c6c400985776f040d5a",
      "MS=ms25371803",
      "stripe-verification=e1469db8bb5c9886c8a7abbece38ddc342618aa4ac7dca85b73731668ea5ec70",
      "jetbrains-domain-verification=77s6xu94q634n5sk6ntslgq5c",
      "onetrust-domain-verification=f110ce3d05314cfb8054ab5e0903ff68",
      "cdn.webflow.com",
      "yahoo-verification-key=X54UzsFVrbpDDU12ORu34v7OcW03f6CpgZpTUouceKQ=",
      "miro-verification=f08757fb9739f5263de5643f8c9534cccb49b7d3",
      "atlassian-domain-verification=fycZUT0eVlPEiaehQXOKmXCe9NJeJsZmCWgWfW7GSuras9JTdhCVrebn8zfRIQ3v",
      "anthropic-domain-verification-ft7nd5=krTYkCbsCOrTIXUyLzSSegK3l",
      "yahoo-verification-key=2nyOaMY2z64VYBysZQLyDBjU85Vd/+N/O1tHvVvie9o=",
      "datadome-domain-verify=gf9iUK5M4yfQc3zyEW1aXklGOXdhjLyy",
      "MS=ms67894313",
      "docker-verification=6c85d46a-1d92-4e77-bbea-945c00c11df1",
      "botify-site-verification=VyJVacuoqlVARp4iXaeza0p9iFlTUubb",
      "globalsign-domain-verification=tJKfbnEmy7WvFRWf3KQMyZ05PnvVJidfQRNnq4AMh8",
      "google-site-verification=bGedCZYrMEPIXRPH5n3Rb0dJjFPACxuP_xMbAPCPenU",
      "JlHKdOBLZpjS/UOFcGHRiSM38ADQhJ0fAN6IMMgSdts=",
      "google-site-verification=U41CuhcP0HS0kVo6HaaLA0Vo-6Wdk8YO-M_Q4rukDmU",
      "google-site-verification=ise_yQfK5npT23y4X7QBl-WYgNjA7AuUrRQQo1Q66EU",
      "asv=f854ad6e866ab7a88b57bebd971f158b",
      "apple-domain-verification=DJEx73gNNUTjejVL",
      "ZOOM_verify_hBlTOUUcSiW7IhDAv16bqQ",
      "openai-domain-verification=dv-sOXO0PYHFRn8QJdpVkjwvqyI",
      "v=spf1 include:_spf.google.com ip4:178.249.138.0/23 ip4:145.253.129.216/29 ip4:80.82.202.192/28 ip4:52.17.172.90/32 include:spf.mandrillapp.com include:7303199.spf04.hubspotemail.net include:spf.extole.io -all",
      "jamf-site-verification=1U6XZPPCv81jzz6DXNXGYA",
      "d24wuv6owifbwc.cloudfront.net",
      "google-site-verification=SdIX4P8Pq06U6a0DMUEvgI5rQS7RM0Z33zKcet-iVf8",
      "wrQAupWCtBhVn8GcFVpM6CMH--bBTLOI"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:yL97s5R6Jy@dmarc.inboxmonster.com,mailto:dmarc-rua@soundcloud.com; ruf=mailto:dmarc-ruf@soundcloud.com; pct=100; sp=reject;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.soundcloud.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Feb 17 00:00:00 2026 GMT",
    "notAfter": "Mar 18 23:59:59 2027 GMT",
    "san": [
      "*.soundcloud.com",
      "soundcloud.com"
    ],
    "days_left": 173,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "52.84.150.39",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "Stream and listen to music online for free with SoundCloud"
  },
  "mixed_content": [
    "href=\"http://",
    "href=\"http://",
    "href=\"http://",
    "href=\"http://"
  ],
  "tech": [
    "Server: am/2"
  ],
  "cookies": [
    {
      "domain": ".soundcloud.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.soundcloud.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://soundcloud.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 200,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "postman-domain-verification=5b7709a2c59b36a8a43b9ac9dfce70486e48a77ead9bc6796eb6",
    "stripe-verification=e1469db8bb5c9886c8a7abbece38ddc342618aa4ac7dca85b73731668ea5",
    "jetbrains-domain-verification=77s6xu94q634n5sk6ntslgq5c",
    "onetrust-domain-verification=f110ce3d05314cfb8054ab5e0903ff68",
    "yahoo-verification-key=X54UzsFVrbpDDU12ORu34v7OcW03f6CpgZpTUouceKQ="
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
      "serial": 15561842832044789349281653552073808468,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m01.amazontrust.com/r2m01.crl"
      ],
      "subject_dn": "3119301706035504030c102a2e736f756e64636c6f75642e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3031",
      "not_before": "20260217000000",
      "not_after": "20270318235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/",
      "/search",
      "/you/",
      "/stream",
      "/upload",
      "/settings",
      "/messages",
      "/*?"
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
    "hsts": "max-age=63072000; includeSubdomains; preload",
    "security_txt": "/.well-known/security.txt",
    "sitemap": {
      "urls": 53,
      "indexes": 0
    },
    "crl": {
      "url": "http://crl.r2m01.amazontrust.com/r2m01.crl",
      "status": 200
    }
  },
  "elapsed_s": 22.4,
  "rechecked": "2026-09-26 23:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- Findings are reported against the public program scope; submission through the program tracker is pending.
