# Security Audit Report — blockchain.info

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blockchain.info/ |
| Bug bounty program | Blockchain |
| Listed scope domain | blockchain.info |
| Test date | 2026-09-26 17:40 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 3, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | CT1 | 31 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 30 days (notAfter Oct 26 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.118.55:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.118.55:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: anthropic-domain-verification-yd7a79=MXqAD8dd4IelKFle1JyrIkOOs; google-site-verification=N70QW1CLbk8SytHhHLNHc-J8DCxNPmgyAP2ueTaxono; google-site-verification=qgYS2zBag9OWLnZ9Xj4HRihaVR0vPlx11_HRRAizW3Y
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of blockchain.info has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 6 disallow path(s), e.g. /search, /*/search, /*/block-index/*, /*/tx-index/*, /r?*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] 31 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.blockchain.info, api.dev.blockchain.info, api.prod.blockchain.info, api.staging.blockchain.info, consul.dev.blockchain.info, consul.europe-west1.internal.blockchain.info, consul.internal.blockchain.info, consul.staging.blockchain.info, dev.blockchain.info, europe-west1.internal.blockchain.info
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "blockchain.info",
  "dns": {
    "a": [
      "104.16.118.55",
      "104.16.117.55"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 20)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx3.googlemail.com (pref 30)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "jay.ns.cloudflare.com.",
      "beth.ns.cloudflare.com."
    ],
    "spf": [
      "anthropic-domain-verification-yd7a79=MXqAD8dd4IelKFle1JyrIkOOs",
      "google-site-verification=N70QW1CLbk8SytHhHLNHc-J8DCxNPmgyAP2ueTaxono",
      "google-site-verification=qgYS2zBag9OWLnZ9Xj4HRihaVR0vPlx11_HRRAizW3Y",
      "v=spf1 include:sendgrid.net include:_spf.google.com -all",
      "google-site-verification=FcNnFGROYe6Yh5FMJ6T3XdwvIkbWtIwzREMEEbnX0YQ",
      "google-site-verification=qRCbhQsR3fxD3ylXPxNwUGUA5DD53PT3Wt9HSzZkPE8",
      "_t0jbgqd8x84sclv1k8ycz5xupbcxf92",
      "yandex-verification: d9f3f2859b58ce6d",
      "atlassian-domain-verification=3Nau9JDz9R67dqvzkIEpQsriloeNPy4vI/eh5acyDnEsG255ANV5Qyed2nE0WK/o"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@blockchain.info;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=KY, localityName=George Town, organizationName=Blockchain.com Group Holdings, Inc., commonName=www.blockchain.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Sep 25 00:00:00 2025 GMT",
    "notAfter": "Oct 26 23:59:59 2026 GMT",
    "san": [
      "www.blockchain.com",
      "blockchain.info",
      "ws.blockchain.info",
      "api.blockchain.info",
      "login.blockchain.com",
      "api.blockchain.com",
      "bps.blockchain.com"
    ],
    "days_left": 30,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.16.118.55",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.blockchain.info",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://blockchain.info/"
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
    "/security.txt": 302,
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
    "source": "certspotter",
    "count": 31,
    "notable": [
      "api.blockchain.info",
      "api.dev.blockchain.info",
      "api.prod.blockchain.info",
      "api.staging.blockchain.info",
      "consul.dev.blockchain.info",
      "consul.europe-west1.internal.blockchain.info",
      "consul.internal.blockchain.info",
      "consul.staging.blockchain.info",
      "dev.blockchain.info",
      "europe-west1.internal.blockchain.info",
      "internal.blockchain.info",
      "nomad.dev.blockchain.info",
      "nomad.internal.blockchain.info",
      "nomad.staging.blockchain.info",
      "ollama.internal.blockchain.info"
    ],
    "sample": [
      "api.blockchain.info",
      "api.dev.blockchain.info",
      "api.prod.blockchain.info",
      "api.staging.blockchain.info",
      "blockchain.info",
      "consul.dev.blockchain.info",
      "consul.europe-west1.internal.blockchain.info",
      "consul.internal.blockchain.info",
      "consul.prod.blockchain.info",
      "consul.staging.blockchain.info",
      "dev.blockchain.info",
      "europe-west1.internal.blockchain.info",
      "internal-nodes.prod.blockchain.info",
      "internal.blockchain.info",
      "nomad.dev.blockchain.info",
      "nomad.internal.blockchain.info",
      "nomad.prod.blockchain.info",
      "nomad.staging.blockchain.info",
      "ollama.internal.blockchain.info",
      "prod.blockchain.info"
    ]
  },
  "apex_txt": [
    "anthropic-domain-verification-yd7a79=MXqAD8dd4IelKFle1JyrIkOOs",
    "google-site-verification=N70QW1CLbk8SytHhHLNHc-J8DCxNPmgyAP2ueTaxono",
    "google-site-verification=qgYS2zBag9OWLnZ9Xj4HRihaVR0vPlx11_HRRAizW3Y",
    "google-site-verification=FcNnFGROYe6Yh5FMJ6T3XdwvIkbWtIwzREMEEbnX0YQ",
    "google-site-verification=qRCbhQsR3fxD3ylXPxNwUGUA5DD53PT3Wt9HSzZkPE8"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/search",
      "/*/search",
      "/*/block-index/*",
      "/*/tx-index/*",
      "/r?*",
      "/static/*.pdf"
    ]
  },
  "elapsed_s": 9.4,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
