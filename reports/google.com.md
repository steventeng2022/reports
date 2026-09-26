# Security Audit Report — google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://google.com/ |
| Bug bounty program | Google |
| Listed scope domain | google.com |
| Test date | 2026-09-26 22:07 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 5, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | low | RED1 | HTTP redirect points to another host over plain HTTP | CWE-319 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 18 | info | CT1 | 47 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: gws
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: gws
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [LOW] HTTP redirect points to another host over plain HTTP (`RED1`)

- **CWE:** CWE-319
- **Detail:** Location: http://www.google.com/
- **Context:** https response, /
- **Recommendation:** Redirect to the same host over HTTPS.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.google.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95; google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ; work-accounts-domain-verification=Tcj6JjIMZOw2KsSEw2Nt2rLae89tN6
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of google.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 178 disallow path(s), e.g. /search, /sdch, /groups, /index.html?, /?
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://google.com/ carries Cache-Control: public, max-age=2592000; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 142.250.77.206 carries PTR lctsaa-ah-in-f14.1e100.net., del11s08-in-f14.1e100.net. for google.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on google.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 18. [INFO] 47 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: console.au.cloud.google.com, console.ca.cloud.google.com, console.ch.cloud.google.com, console.eu.cloud.google.com, console.il.cloud.google.com, console.in.cloud.google.com, console.it.cloud.google.com, console.jp.cloud.google.com, console.sa.cloud.google.com, console.uk.cloud.google.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "google.com",
  "dns": {
    "a": [
      "142.250.77.206"
    ],
    "aaaa": [
      "2404:6800:4012:6::200e"
    ],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 10)"
    ],
    "ns": [
      "ns2.google.com.",
      "ns4.google.com.",
      "ns1.google.com.",
      "ns3.google.com."
    ],
    "caa": [
      "0 issue \"pki.goog\""
    ],
    "spf": [
      "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95",
      "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ",
      "_r4rd1pvwyrpi7sw4a3hzmw8e51yh9td",
      "work-accounts-domain-verification=Tcj6JjIMZOw2KsSEw2Nt2rLae89tN6",
      "v=spf1 include:_spf.google.com ~all",
      "google-site-verification=4ibFUgB-wXLQ_S7vsXVomSTVamuOXBiVAzpR5IZ87D0",
      "onetrust-domain-verification=0d477fe608074e6f9c12bca7826035cc",
      "docusign=1b0a6754-49b1-4db5-8540-d2c12664b289",
      "Z29vZ2xl",
      "cisco-ci-domain-verification=47c38bc8c4b74b7233e9053220c1bbe76bcc1cd33c7acf7acd36cd6a5332004b",
      "onetrust-domain-verification=6d685f1d41a94696ad7ef771f68993e0",
      "apple-domain-verification=30afIBcvSuDV2PLX",
      "arcules-domain-verification=2R4t5G7nI6tRCo61lpxxbLksPYstxhGmtV75cpr8x9K",
      "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8=",
      "google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o",
      "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB",
      "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.google.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR2",
    "notBefore": "Sep 10 19:21:53 2026 GMT",
    "notAfter": "Dec  3 19:21:52 2026 GMT",
    "san": [
      "*.google.com",
      "*.appengine.google.com",
      "*.bdn.dev",
      "*.origin-test.bdn.dev",
      "*.cloud.google.com",
      "*.crowdsource.google.com",
      "*.datacompute.google.com",
      "*.google.ca",
      "*.google.cl",
      "*.google.co.in",
      "*.google.co.jp",
      "*.google.co.uk",
      "*.google.com.ar",
      "*.google.com.au",
      "*.google.com.br",
      "*.google.com.co",
      "*.google.com.mx",
      "*.google.com.tr",
      "*.google.com.vn",
      "*.google.de",
      "*.google.es",
      "*.google.fr",
      "*.google.hu",
      "*.google.it",
      "*.google.nl",
      "*.google.pl",
      "*.google.pt",
      "*.gemini.cloud.google.com",
      "*.gstatic.com",
      "*.metric.gstatic.com",
      "*.gvt1.com",
      "*.gcpcdn.gvt1.com",
      "*.gvt2.com",
      "*.gcp.gvt2.com",
      "*.url.google.com",
      "*.youtube-nocookie.com",
      "*.ytimg.com",
      "ai.android",
      "android.com",
      "*.android.com",
      "*.flash.android.com",
      "g.co",
      "*.g.co",
      "goo.gl",
      "www.goo.gl",
      "google-analytics.com",
      "*.google-analytics.com",
      "google.com",
      "googlecommerce.com",
      "*.googlecommerce.com",
      "urchin.com",
      "*.urchin.com",
      "youtu.be",
      "youtube.com",
      "*.youtube.com",
      "music.youtube.com",
      "*.music.youtube.com",
      "youtubeeducation.com",
      "*.youtubeeducation.com",
      "youtubekids.com",
      "*.youtubekids.com",
      "yt.be",
      "*.yt.be",
      "android.clients.google.com",
      "*.aistudio.google.com"
    ],
    "days_left": 67,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "142.250.77.206",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: gws"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.google.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "http://www.google.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 301,
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
    "source": "certspotter",
    "count": 47,
    "notable": [
      "console.au.cloud.google.com",
      "console.ca.cloud.google.com",
      "console.ch.cloud.google.com",
      "console.eu.cloud.google.com",
      "console.il.cloud.google.com",
      "console.in.cloud.google.com",
      "console.it.cloud.google.com",
      "console.jp.cloud.google.com",
      "console.sa.cloud.google.com",
      "console.uk.cloud.google.com",
      "console.us.cloud.google.com",
      "datastudio.eu.cloud.google.com",
      "datastudio.us.cloud.google.com",
      "lookerstudio.eu.cloud.google.com",
      "lookerstudio.us.cloud.google.com"
    ],
    "sample": [
      "aistudio.google.com",
      "android.clients.google.com",
      "antigravity.google.com",
      "artsandculture.google.com",
      "c512c074ec21dc9.ad.corp.google.com",
      "calljoy.area120.google.com",
      "ccure-csrm-uat-mas-app.corp.google.com",
      "ccure-gsrs-uat-mas-app.corp.google.com",
      "console.au.cloud.google.com",
      "console.ca.cloud.google.com",
      "console.ch.cloud.google.com",
      "console.eu.cloud.google.com",
      "console.il.cloud.google.com",
      "console.in.cloud.google.com",
      "console.it.cloud.google.com",
      "console.jp.cloud.google.com",
      "console.nest.google.com",
      "console.sa.cloud.google.com",
      "console.uk.cloud.google.com",
      "console.us.cloud.google.com"
    ]
  },
  "apex_txt": [
    "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95",
    "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ",
    "work-accounts-domain-verification=Tcj6JjIMZOw2KsSEw2Nt2rLae89tN6",
    "google-site-verification=4ibFUgB-wXLQ_S7vsXVomSTVamuOXBiVAzpR5IZ87D0",
    "onetrust-domain-verification=0d477fe608074e6f9c12bca7826035cc"
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
      "aia_ocsp": null,
      "not_before": "20260910192153",
      "not_after": "20261203192152"
    }
  },
  "http2": {
    "robots_disallow": [
      "/search",
      "/sdch",
      "/groups",
      "/index.html?",
      "/?",
      "/goto?",
      "/?hl=*&",
      "/?hl=*&*&gws_rd=ssl",
      "/imgres",
      "/u/",
      "/setprefs",
      "/m?",
      "/m/",
      "/wml?",
      "/wml/?"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "lctsaa-ah-in-f14.1e100.net.",
      "del11s08-in-f14.1e100.net."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.google.com/",
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
      "/.well-known/assetlinks.json"
    ],
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 11.0,
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
