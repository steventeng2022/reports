# Security Audit Report — fbi.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://fbi.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | fbi.gov |
| Test date | 2026-09-26 16:42 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 3, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | CT1 | 424 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 14 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.148.244:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.148.244:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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

### 13. [INFO] 424 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: alpha-sifts-staging.apps.dcap.fbi.gov, alpha-sifts.apps.dcap.fbi.gov, api.fbi.gov, api.sos.fbi.gov, avalanche.dv.apps.dcap.fbi.gov, avalanche.va.apps.dcap.fbi.gov, circe.va.apps.dcap.fbi.gov, denali.dv.apps.dcap.fbi.gov, denali.va.apps.dcap.fbi.gov, frost.va.apps.dcap.fbi.gov
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 14. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: alpha-sifts-staging.apps.dcap.fbi.gov, alpha-sifts.apps.dcap.fbi.gov, api.sos.fbi.gov; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "fbi.gov",
  "dns": {
    "a": [
      "104.16.148.244",
      "104.16.149.244"
    ],
    "aaaa": [
      "2606:4700::6810:94f4",
      "2606:4700::6810:95f4"
    ],
    "cname": null,
    "mx": [
      "mx-west.fbi.gov (pref 20)",
      "mx-east.fbi.gov (pref 10)"
    ],
    "ns": [
      "ns-cloud-e3.googledomains.com.",
      "ns-cloud-e1.googledomains.com.",
      "ns-cloud-e2.googledomains.com.",
      "ns-cloud-e4.googledomains.com."
    ],
    "spf": [
      "C8WWN4MbK7z5BL4Ivc/DSxEeVsr18DB5/P8GxlM1S3OfCxexrFpFzpY7MBDBoid3h/OxYU+1H0pFrKWhj1j3cw==",
      "v=spf1 +mx ip4:153.31.0.0/16 -all",
      "MS=ms39271050",
      "kiro-site-verification=31a85f50-8d2b-4be7-9175-d16a469190ee",
      "ublrZj1CzpSEiwtiRFKDAyiek8hRqkqaTTApxvhwai14i8JqVBOauW4cA06i39H5Lhl3HnALCM/xfTxIPEXEpA==",
      "adobe-idp-site-verification=101945e35b37c6efd526cf706f04bc9545a02f9cdc58dbf718678c506697d67d",
      "google-site-verification=L8cauHJF4MANoTCkMbrLkAVfHBta28ctva9n1IDekTo",
      "625558384-8740534",
      "google-gws-recovery-domain-verification=74752930",
      "_globalsign-domain-verification=xZMJnzdDAgURaBjUZ6qbqWaaYmV5W3sfo3TF8mUxne",
      "amazonses: iUbfpGEqhMPlcmJ0aykJZREltK6pWio9wOgRngnJOQE=",
      "google-site-verification=6UEk-jfg1xPNjz_rQGcRFJOBGxMy1aARDZUTXgSNAqw",
      "google-site-verification=uTH4Vg-Xcc9hTqSdeThbT9UnYvuphObtVSpCEgaGr78",
      "apple-domain-verification=oOspXl6Jvnx9HzLM"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-feedback@fbi.gov,mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:dmarc-feedback@fbi.gov; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=fbi.gov",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 14 12:18:41 2026 GMT",
    "notAfter": "Dec 13 13:18:21 2026 GMT",
    "san": [
      "fbi.gov",
      "*.fbi.gov"
    ],
    "days_left": 77,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.16.148.244",
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
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "fbi.gov",
      "samesite": "none"
    },
    {
      "domain": "fbi.gov",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.fbi.gov",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://fbi.gov/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 424,
    "notable": [
      "alpha-sifts-staging.apps.dcap.fbi.gov",
      "alpha-sifts.apps.dcap.fbi.gov",
      "api.fbi.gov",
      "api.sos.fbi.gov",
      "avalanche.dv.apps.dcap.fbi.gov",
      "avalanche.va.apps.dcap.fbi.gov",
      "circe.va.apps.dcap.fbi.gov",
      "denali.dv.apps.dcap.fbi.gov",
      "denali.va.apps.dcap.fbi.gov",
      "frost.va.apps.dcap.fbi.gov",
      "gw-tidal.dv.apps.dcap.fbi.gov",
      "gw-user-portal.dv.apps.dcap.fbi.gov",
      "jira.cjis.fbi.gov",
      "jira.ctp-prev.cjis.fbi.gov",
      "lenz.dv.apps.dcap.fbi.gov"
    ],
    "sample": [
      "acts-csdb-ndcac.fbi.gov",
      "acts-ndcac.fbi.gov",
      "adfs-elab.fbi.gov",
      "adfs-ndcac.fbi.gov",
      "admincenter.certauth.fbi.gov",
      "admincenter.certauth.fs1.fbi.gov",
      "admincenter.fact.fbi.gov",
      "alpha-sifts-staging.apps.dcap.fbi.gov",
      "alpha-sifts.apps.dcap.fbi.gov",
      "api.fbi.gov",
      "api.sos.fbi.gov",
      "archives.fbi.gov",
      "artcrimes.fbi.gov",
      "askcalea.fbi.gov",
      "astra.va.fbi.gov",
      "atlas.fbi.gov",
      "atlasbeta.fbi.gov",
      "autodiscover.fbi.gov",
      "autodiscover.ic.fbi.gov",
      "avalanche.dv.apps.dcap.fbi.gov"
    ],
    "dangling": [
      "alpha-sifts-staging.apps.dcap.fbi.gov",
      "alpha-sifts.apps.dcap.fbi.gov",
      "api.sos.fbi.gov"
    ]
  },
  "elapsed_s": 30.5,
  "rechecked": "2026-09-26 16:42 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
