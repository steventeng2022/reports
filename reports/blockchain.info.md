# Security Audit Report — blockchain.info

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blockchain.info/ |
| Bug bounty program | Blockchain |
| Listed scope domain | blockchain.info |
| Test date | 2026-09-25 08:44 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 2, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | CT1 | 31 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.118.55:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.118.55:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] 31 hostnames found via Certificate Transparency (certspotter) (`CT1`)

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
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)",
      "aspmx3.googlemail.com (pref 30)",
      "aspmx2.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "beth.ns.cloudflare.com.",
      "jay.ns.cloudflare.com."
    ],
    "spf": [
      "yandex-verification: d9f3f2859b58ce6d",
      "v=spf1 include:sendgrid.net include:_spf.google.com -all",
      "google-site-verification=qRCbhQsR3fxD3ylXPxNwUGUA5DD53PT3Wt9HSzZkPE8",
      "atlassian-domain-verification=3Nau9JDz9R67dqvzkIEpQsriloeNPy4vI/eh5acyDnEsG255ANV5Qyed2nE0WK/o",
      "google-site-verification=FcNnFGROYe6Yh5FMJ6T3XdwvIkbWtIwzREMEEbnX0YQ",
      "anthropic-domain-verification-yd7a79=MXqAD8dd4IelKFle1JyrIkOOs",
      "google-site-verification=N70QW1CLbk8SytHhHLNHc-J8DCxNPmgyAP2ueTaxono",
      "_t0jbgqd8x84sclv1k8ycz5xupbcxf92",
      "google-site-verification=qgYS2zBag9OWLnZ9Xj4HRihaVR0vPlx11_HRRAizW3Y"
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
    "days_left": 31,
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
  "elapsed_s": 163.3,
  "rechecked": "2026-09-25 10:43 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
