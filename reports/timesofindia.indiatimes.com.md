# Security Audit Report — timesofindia.indiatimes.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://timesofindia.indiatimes.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | timesofindia.indiatimes.com |
| Test date | 2026-09-25 10:22 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 2, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Bhoot
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=93600
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=86400 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Bhoot
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

## Evidence (raw response observations)

```json
{
  "domain": "timesofindia.indiatimes.com",
  "dns": {
    "a": [
      "104.116.243.96",
      "104.116.243.83"
    ],
    "aaaa": [
      "2600:1417:76::6874:f360",
      "2600:1417:76::6874:f353"
    ],
    "cname": "timesofindia.indiatimes.com-v1.edgekey.net.",
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
    "subject": "commonName=timesofindia.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Jul 29 05:38:37 2026 GMT",
    "notAfter": "Oct 27 05:38:36 2026 GMT",
    "san": [
      "agri-preprod.economictimes.indiatimes.com",
      "agri.economictimes.indiatimes.com",
      "ai-stage.etmasterclass.com",
      "ai.etmasterclass.com",
      "api-newscard.timesofindia.com",
      "autolytics-cms.economictimes.indiatimes.com",
      "b2b-cms.economictimes.indiatimes.com",
      "bengali.economictimes.com",
      "bollywood.indiatimes.com",
      "builder.timesinternet.in",
      "centralised-panel.economictimes.com",
      "cfsummit.vconfex.com",
      "chemicals-preprod.economictimes.indiatimes.com",
      "chemicals.economictimes.indiatimes.com",
      "ciosea-cms.economictimes.indiatimes.com",
      "ciosea-stage.economictimes.indiatimes.com",
      "ciosea.economictimes.indiatimes.com",
      "ciosea.vconfex.com",
      "crypto-preprod.economictimes.indiatimes.com",
      "crypto.economictimes.indiatimes.com",
      "denmarkdocument.timesinternet.in",
      "etagriculture.com",
      "etchemicals.in",
      "etcryptoworld.com",
      "etinfra.com",
      "etmailapi.economictimes.com",
      "etpay.economictimes.indiatimes.com",
      "etpetrochem.com",
      "etsmesummit.com",
      "etsmesummits.co.in",
      "etsmesummits.com",
      "etsmesummits.in",
      "etsmesummits.net.in",
      "etsupplychain.in",
      "etsustainability.com",
      "events.shalinamedspace.com",
      "fashion.indiatimes.com",
      "football.indiatimes.com",
      "gujarati.economictimes.com",
      "hindi.economictimes.com",
      "hollywood.indiatimes.com",
      "hrme-cms.economictimes.indiatimes.com",
      "hrme-stage.economictimes.indiatimes.com",
      "hrme.economictimes.indiatimes.com",
      "hrme.vconfex.com",
      "hrsea-cms.economictimes.indiatimes.com",
      "hrsea-stage.economictimes.indiatimes.com",
      "hrsea.economictimes.indiatimes.com",
      "hrsea.vconfex.com",
      "id.economictimes.indiatimes.com",
      "infra-stage.economictimes.indiatimes.com",
      "infra.economictimes.indiatimes.com",
      "infra.vconfex.com",
      "kannada.economictimes.com",
      "m.score.toi.in",
      "m.timesofindia.com",
      "malayalam.economictimes.com",
      "marathi.economictimes.com",
      "movie.indiatimes.com",
      "nbtfeed.indiatimes.com",
      "oauth.economictimes.indiatimes.com",
      "pay-admin.economictimes.indiatimes.com",
      "photo.indiatimes.com",
      "photos.indiatimes.com",
      "smesummits.com",
      "sport.indiatimes.com",
      "sports.indiatimes.com",
      "sso-stage.economictimes.indiatimes.com",
      "support.etportfolio.economictimes.indiatimes.com",
      "sustainability-preprod.economictimes.indiatimes.com",
      "sustainability.economictimes.indiatimes.com",
      "tamil.economictimes.com",
      "tech.indiatimes.com",
      "technology.indiatimes.com",
      "telugu.economictimes.com",
      "timesastro.com",
      "timesjobs.com",
      "timesofindia.com",
      "timesofindia.indiatimes.com",
      "tnl.indiatimes.com",
      "toispastaging.indiatimes.com",
      "tprime.co",
      "trailer.indiatimes.com",
      "trailers.indiatimes.com",
      "video.indiatimes.com",
      "www.ai.etmasterclass.com",
      "www.etinfra.com",
      "www.etsmesummit.com",
      "www.etsmesummits.co.in",
      "www.etsmesummits.com",
      "www.etsmesummits.in",
      "www.etsmesummits.net.in",
      "www.m.timesofindia.com",
      "www.smesummits.com",
      "www.thelearningcurve.ai",
      "www.timesastro.com",
      "www.timesjobs.com",
      "www.timesofindia.com",
      "www.timesofindia.indiatimes.com"
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
    "ip": "104.116.243.96",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "Times of India"
  },
  "mixed_content": [],
  "tech": [
    "Server: Bhoot"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": "false"
    },
    {
      "origin": "https://sub.timesofindia.indiatimes.com",
      "acao": "",
      "acac": "false"
    }
  ],
  "http": {
    "status": 200
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
    "/.well-known/security.txt": 404,
    "/security.txt": 200,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 403,
    "/api/": 200
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 47.4,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
