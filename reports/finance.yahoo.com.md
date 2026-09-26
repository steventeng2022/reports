# Security Audit Report — finance.yahoo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://finance.yahoo.com/ |
| Bug bounty program | Yahoo! |
| Listed scope domain | finance.yahoo.com |
| Test date | 2026-09-26 17:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 7 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 8 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 11 days (notAfter Oct  7 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ATS
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ATS
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of finance.yahoo.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 7. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but finance.yahoo.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 8. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 56 disallow path(s), e.g. /screener/insider/, /caas/, /fin_ms/, /r/, /_finance_doubledown/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "finance.yahoo.com",
  "dns": {
    "a": [
      "180.222.109.251",
      "180.222.109.252"
    ],
    "aaaa": [
      "2406:2000:a0:807::2",
      "2406:2000:a0:807::1"
    ],
    "cname": "fo-finance-ycpi-cf.gycpi.b.yahoodns.net.",
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
    "days_left": 11,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "180.222.109.251",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Yahoo Finance - Stock Market Live, Quotes, Business &amp; Finance News"
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
      "origin": "https://sub.finance.yahoo.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://finance.yahoo.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 429,
    "/.htaccess": 429,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "cname_chain": [
    "fo-finance-ycpi-cf.gycpi.b.yahoodns.net"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/screener/insider/",
      "/caas/",
      "/fin_ms/",
      "/r/",
      "/_finance_doubledown/",
      "/nel_ms/",
      "/caas/",
      "/__rapidworker-1.2.js",
      "/__blank",
      "/_td_api",
      "/_remote",
      "/xhr",
      "/rmp",
      "/pdarla/",
      "/sdarla/"
    ]
  },
  "elapsed_s": 11.0,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
