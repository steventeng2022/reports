# Security Audit Report — twitter.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://twitter.com/ |
| Bug bounty program | Twitter |
| Listed scope domain | twitter.com |
| Test date | 2026-09-26 22:17 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 2, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 14 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 15 | low | RD2 | HTTPS root redirects to a different domain | CWE-200 |
| 16 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 17 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.140.229:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.140.229:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare envoy; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare envoy
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.twitter.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

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
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=j6u0o1PTkobCXC84uEF/sWpIPtaZURBVYqKzmTvT8wugLcHT1v; slack-domain-verification=9oO8P4Glf4252QJDOg4rHGs6KlSkBuI5ZVmWRO8d; google-site-verification=q1ghWjGLX9Ba-Gy_B4n_pAgC_mQYzWmQpOD8CMWl_Hw
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of twitter.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 45 disallow path(s), e.g. /*?lang=en-ss, /search/realtime, /search/users, /search/*/grid, /*/analytics
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of twitter.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 14. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on twitter.com indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 15. [LOW] HTTPS root redirects to a different domain (`RD2`)

- **CWE:** CWE-200
- **Detail:** https://twitter.com/ answered 301 with Location: https://x.com/ (cross-domain handoff at the entry point).
- **Recommendation:** Review the cross-domain redirect; it discloses the real entry point and can be abused in open-redirect-style flows.

### 16. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on twitter.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 17. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for twitter.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

## Evidence (raw response observations)

```json
{
  "domain": "twitter.com",
  "dns": {
    "a": [
      "162.159.140.229"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "d.u06.twtrdns.net.",
      "b.r06.twtrdns.net.",
      "b.u06.twtrdns.net.",
      "c.r06.twtrdns.net.",
      "a.u06.twtrdns.net.",
      "a.r06.twtrdns.net.",
      "c.u06.twtrdns.net.",
      "d.r06.twtrdns.net."
    ],
    "caa": [],
    "spf": [
      "traction-guest=a4d0248d-fe01-4222-8fcc-33f68323e667",
      "atlassian-domain-verification=j6u0o1PTkobCXC84uEF/sWpIPtaZURBVYqKzmTvT8wugLcHT1vvrzzA63iP1qSLN",
      "slack-domain-verification=9oO8P4Glf4252QJDOg4rHGs6KlSkBuI5ZVmWRO8d",
      "v=spf1 ip4:199.16.156.0/22 ip4:199.59.148.0/22 ip4:8.25.194.0/23 ip4:8.25.196.0/23 ip4:204.92.114.203 ip4:204.92.114.204/31 include:_spf.google.com include:_thirdparty.twitter.com -all",
      "traction-guest=6882b04e-4188-4ff9-8bb4-bff5a3d358e6",
      "google-site-verification=q1ghWjGLX9Ba-Gy_B4n_pAgC_mQYzWmQpOD8CMWl_Hw",
      "adobe-idp-site-verification=a2ff8fc40c434d1d6f02f68b0b1a683e400572ab8c1f2c180c71c3d985b9270a",
      "stripe-verification=46F7B88485621DC18923B43D12E90E6CDBCE232F2FEBCF084E6EFA91F6BA707D",
      "MS=BEE202D20C326867290BDEFA2DDDF4594B5D6860",
      "linear-domain-verification=t5iq7e7nbw5w",
      "google-site-verification=600dQ0pZYsH2xOFt4hYmf5f5NpjCbWE_qk5Y04dErYM",
      "google-site-verification=P9-NRZ0gaRKRGNDOXOjct5XETPtr3P9D-XA8HnlbAy4",
      "google-site-verification=h6dJIv0HXjLOkGAotLAWEzvoi9SxqP4vjpx98vrCvvQ",
      "google-site-verification=TNhAkfLUeIbzzzSgPNxS5aEkKMf3aUcpPmCK1_kmIvU",
      "miro-verification=6e1ca9ad6d0c2cd2e4186141265f23ed618cfe37",
      "bj6sbt5xqs9hw9jrfvz7hplrg0l680sb",
      "0a8c0fc6-bfa5-4ea7-b09b-87f2989022d6",
      "wrike-verification=MjU4MTA5MjoyN2UzNDc1MjU3MDZiZTY4NjBiNzliNDQ2OTUwNWY3NmM5NDgyMTBlYzFkNTcwYTE2YWNmZDdkNTY2ZmE4Yzlh",
      "apple-domain-verification=zd1iHoEO9LILEQIq",
      "canva-site-verification=lMnZ3wMh7c1uqZqa-cxZTg",
      "loom-site-verification=638c6bc173b9458997f64d305bf42499",
      "mixpanel-domain-verify=164dda91-31f4-41e8-a816-0f59b38fea30",
      "notion-domain-verification=uKi5TAGxlhWMHG9uHKHkDY3cVc6zraAE1I44bILENlB",
      "google-site-verification=F2uUiLUsD6kQlpUVQzxUM3PHa0uPo5GBS84SCG8QwXI"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:d3omt-8484@rua.dmarc.emailanalyst.com; ruf=mailto:d3omt-8484@ruf.dmarc.emailanalyst.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.twitter.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug 14 17:48:02 2026 GMT",
    "notAfter": "Nov 12 17:48:01 2026 GMT",
    "san": [
      "*.twitter.com",
      "cdn.syndication.twitter.com",
      "twitter.com"
    ],
    "days_left": 46,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "162.159.140.229",
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
    "Server: cloudflare envoy",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": ".twitter.com",
      "samesite": "none"
    },
    {
      "domain": ".twitter.com",
      "samesite": "none"
    },
    {
      "domain": ".twitter.com",
      "samesite": "none"
    },
    {
      "domain": ".twitter.com",
      "samesite": "none"
    },
    {
      "domain": "twitter.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "https://evil-auditor.example",
      "acac": ""
    },
    {
      "origin": "https://sub.twitter.com",
      "acao": "https://sub.twitter.com",
      "acac": ""
    }
  ],
  "http": {
    "status": 520
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "atlassian-domain-verification=j6u0o1PTkobCXC84uEF/sWpIPtaZURBVYqKzmTvT8wugLcHT1v",
    "slack-domain-verification=9oO8P4Glf4252QJDOg4rHGs6KlSkBuI5ZVmWRO8d",
    "google-site-verification=q1ghWjGLX9Ba-Gy_B4n_pAgC_mQYzWmQpOD8CMWl_Hw",
    "adobe-idp-site-verification=a2ff8fc40c434d1d6f02f68b0b1a683e400572ab8c1f2c180c71",
    "stripe-verification=46F7B88485621DC18923B43D12E90E6CDBCE232F2FEBCF084E6EFA91F6BA"
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
      "aia_ocsp": null,
      "not_before": "20260814174802",
      "not_after": "20261112174801"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/*?lang=en-ss",
      "/search/realtime",
      "/search/users",
      "/search/*/grid",
      "/*/analytics",
      "/*/followers",
      "/*/following",
      "/*/verified_followers",
      "/account/deactivated",
      "/settings/deactivated",
      "/*/likes",
      "/*/likes?",
      "/*/retweets",
      "/*/retweets?",
      "/*/media"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://x.com/",
    "http_status": 520,
    "p404_status": 301,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 8.8,
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
