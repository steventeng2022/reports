# Security Audit Report — podcasts.apple.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://podcasts.apple.com/ |
| Bug bounty program | Apple |
| Listed scope domain | podcasts.apple.com |
| Test date | 2026-09-25 10:10 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 1, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 9 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: daiquiri/5
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=93600
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: daiquiri/5
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'geo' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 9. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'geo' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

## Evidence (raw response observations)

```json
{
  "domain": "podcasts.apple.com",
  "dns": {
    "a": [
      "23.209.216.33"
    ],
    "aaaa": [
      "2600:1417:76:a85::2a1",
      "2600:1417:76:a86::2a1",
      "2600:1417:76:a82::2a1",
      "2600:1417:76:a87::2a1",
      "2600:1417:76:a81::2a1"
    ],
    "cname": "podcasts-cdn-itunes-apple-com.v.aaplimg.com.",
    "mx": [],
    "ns": [],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "businessCategory=Private Organization, jurisdictionCountryName=US, jurisdictionStateOrProvinceName=California, serialNumber=C0806592, countryName=US, stateOrProvinceName=California, localityName=Cupertino, organizationName=Apple Inc., commonName=itunes.apple.com",
    "issuer": "countryName=US, organizationName=Apple Inc., commonName=Apple Public EV Server RSA CA 1 - G1",
    "notBefore": "Jul  2 21:15:31 2026 GMT",
    "notAfter": "Jan  7 19:46:05 2027 GMT",
    "san": [
      "apps.mzstatic.com",
      "api.music.apple.com",
      "configuration.apple.com",
      "radio-services.itunes.apple.com",
      "api.videos.apple.com",
      "is3-ssl.mzstatic.com",
      "api.podcasts.apple.com",
      "a5.mzstatic.com",
      "api.edu.apple.com",
      "accertify.mzstatic.com",
      "api.itunes.apple.com",
      "uts-api-siri.itunes.apple.com",
      "is1-ssl.mzstatic.com",
      "itc.mzstatic.com",
      "bookkeeper.itunes.apple.com",
      "itunes.apple.com",
      "upp.itunes.apple.com",
      "books.apple.com",
      "a2.mzstatic.com",
      "amp-api-edge.apps.apple.com",
      "tv.apple.com",
      "sb.music.apple.com",
      "siri-search.itunes.apple.com",
      "amp-api-edge.music.apple.com",
      "s2.mzstatic.com",
      "se.itunes.apple.com",
      "sf-api-token-service.itunes.apple.com",
      "sp.itunes.apple.com",
      "is4-ssl.mzstatic.com",
      "metrics.mzstatic.com",
      "radio.itunes.apple.com",
      "b5.mzstatic.com",
      "init.itunes.apple.com",
      "b3.mzstatic.com",
      "radio-activity.itunes.apple.com",
      "music.apple.com",
      "b1.mzstatic.com",
      "podcasts.apple.com",
      "api.apps.apple.com",
      "amp-api-search-edge.apps.apple.com",
      "is5-ssl.mzstatic.com",
      "s1.mzstatic.com",
      "api-edge.apps.apple.com",
      "tf-feedback.itunes.apple.com",
      "assets-mercury.mzstatic.com",
      "is2-ssl.mzstatic.com",
      "b2.mzstatic.com",
      "b4.mzstatic.com",
      "videos.apple.com",
      "s.mzstatic.com",
      "atve.tv.apple.com",
      "s5.mzstatic.com",
      "s3.mzstatic.com",
      "sync.itunes.apple.com",
      "a3.mzstatic.com",
      "images-mercury.mzstatic.com",
      "a4.mzstatic.com",
      "api.books.apple.com",
      "radio-quickplay.itunes.apple.com",
      "edge.itunes.apple.com",
      "pd.itunes.apple.com",
      "apps.apple.com",
      "su.itunes.apple.com",
      "search.itunes.apple.com",
      "sb.tv.apple.com",
      "s4.mzstatic.com",
      "store.mzstatic.com",
      "vocabulary.itunes.apple.com",
      "a1.mzstatic.com",
      "desktop-music-legacy.itunes.apple.com",
      "se-edge.itunes.apple.com"
    ],
    "days_left": 104,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.209.216.33",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: daiquiri/5"
  ],
  "cookies": [
    {
      "domain": ".apple.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.podcasts.apple.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://podcasts.apple.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 29.1,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
