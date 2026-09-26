# Security Audit Report — news.yahoo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://news.yahoo.com/ |
| Bug bounty program | Yahoo! |
| Listed scope domain | news.yahoo.com |
| Test date | 2026-09-25 10:05 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 12 days (notAfter Oct  7 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ATS
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ATS
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "news.yahoo.com",
  "dns": {
    "a": [
      "180.222.109.252",
      "180.222.109.251"
    ],
    "aaaa": [
      "2406:2000:a0:807::2",
      "2406:2000:a0:807::1"
    ],
    "cname": "me-ycpi-cf.news.g06.yahoodns.net.",
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
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=Yahoo Holdings Inc., commonName=*.www.yahoo.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Aug 17 00:00:00 2026 GMT",
    "notAfter": "Oct  7 23:59:59 2026 GMT",
    "san": [
      "*.www.yahoo.com",
      "*.yahoo.com",
      "ymail.com",
      "s.yimg.com",
      "*.fantasysports.yahoo.com",
      "*.calendar.yahoo.com",
      "*.groups.yahoo.com",
      "*.mail.yahoo.com",
      "*.msg.yahoo.com",
      "*.ymail.com",
      "*.finance.yahoo.com",
      "*.news.yahoo.com",
      "de.nachrichten.yahoo.com",
      "*.video.yahoo.com",
      "*.m.yahoo.com",
      "*.my.yahoo.com",
      "*.search.yahoo.com",
      "*.secure.yahoo.com",
      "*.yahooapis.com",
      "*.mg.mail.yahoo.com",
      "*.api.fantasysports.yahoo.com",
      "*.autos.yahoo.com",
      "*.cricket.yahoo.com",
      "*.football.fantasysports.yahoo.com",
      "*.games.yahoo.com",
      "*.lifestyle.yahoo.com",
      "*.style.yahoo.com",
      "*.movies.yahoo.com",
      "*.mujer.yahoo.com",
      "*.music.yahoo.com",
      "*.safely.yahoo.com",
      "*.screen.yahoo.com",
      "*.shine.yahoo.com",
      "*.sports.yahoo.com",
      "*.travel.yahoo.com",
      "*.tv.yahoo.com",
      "*.weather.yahoo.com",
      "*.notepad.yahoo.com",
      "*.yql.yahoo.com",
      "*.celebrity.yahoo.com",
      "*.ybp.yahoo.com",
      "*.geo.yahoo.com",
      "*.messenger.yahoo.com",
      "*.antispam.yahoo.com",
      "*.ysm.yahoo.com",
      "video.media.yql.yahoo.com",
      "*.iris.yahoo.com",
      "*.mobile.yahoo.com",
      "*.overview.mail.yahoo.com",
      "*.mailplus.mail.yahoo.com",
      "*.xobni.yahoo.com",
      "api.digitalhomeservices.yahoo.com",
      "commsdata.api.yahoo.com",
      "*.commsdata.api.yahoo.com",
      "*.commerce.yahoo.com",
      "*.sombrero.yahoo.net",
      "*.tw.campaign.yahoo.com",
      "*.dispatcher.yahoo.com",
      "cdn.launch3d.com",
      "cdn.js7k.com",
      "video-api.sapi.yahoo.com",
      "*.vto.commerce.yahoo.com",
      "es-us.finanzas.yahoo.com",
      "br.financas.yahoo.com",
      "es-us.noticias.yahoo.com",
      "es-us.vida-estilo.yahoo.com",
      "de.kino.yahoo.com",
      "*.dht.yahoo.com",
      "admetrics.uadapp.yahoo.com",
      "*.gcp.mail.yahoo.com",
      "*.media.yahoo.com",
      "o.aolcdn.com",
      "s.aolcdn.com",
      "ca.rogers.yahoo.com",
      "fr-ca.rogers.yahoo.com",
      "*.test-newsletters.yahoo.com",
      "*.newsletters.yahoo.com",
      "*.email.cc.yahoo.com",
      "*.shopping.comms.yahoo.com",
      "*.activity.yahoo.com",
      "*.notify.yahoo.com",
      "*.today.yahoo.com",
      "*.discover.yahoo.com",
      "*.sync.mail.yahoo.com"
    ],
    "days_left": 12,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "180.222.109.252",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: ATS"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.news.yahoo.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://news.yahoo.com/"
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
    "/.env": 429,
    "/.htaccess": 429,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 24.4,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
