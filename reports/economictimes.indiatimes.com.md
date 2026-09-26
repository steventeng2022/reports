# Security Audit Report — economictimes.indiatimes.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://economictimes.indiatimes.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | economictimes.indiatimes.com |
| Test date | 2026-09-26 18:50 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 4, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 8 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 9 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 14 | info | CT1 | 245 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 15 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=259200
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'geoinfo' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 8. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'geoinfo' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 9. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.economictimes.indiatimes.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of economictimes.indiatimes.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but economictimes.indiatimes.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 199 disallow path(s), e.g. /PDAET/, /7176/, */notify.htm?*, /default1.cms, /default.cms
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 104.116.243.96 carries PTR a104-116-243-96.deploy.static.akamaitechnologies.com. for economictimes.indiatimes.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 14. [INFO] 245 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.economictimes.indiatimes.com, apps.economictimes.indiatimes.com, hr.economictimes.indiatimes.com, img.economictimes.indiatimes.com, payment.economictimes.indiatimes.com, static.economictimes.indiatimes.com, www.hr.economictimes.indiatimes.com, www.infra.economictimes.indiatimes.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 15. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: img.economictimes.indiatimes.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "economictimes.indiatimes.com",
  "dns": {
    "a": [
      "104.116.243.96",
      "104.116.243.83"
    ],
    "aaaa": [
      "2600:1417:76::6874:f360",
      "2600:1417:76::6874:f353"
    ],
    "cname": "economictimes.indiatimes.com-v1.edgekey.net.",
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
    "subject": "commonName=navbharattimes.indiatimes.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug 27 04:53:23 2026 GMT",
    "notAfter": "Nov 25 04:53:22 2026 GMT",
    "san": [
      "1838reserve.com",
      "agriculture.economictimes.indiatimes.com",
      "app.publishstory.co",
      "assets.gadgetsnow.com",
      "assets.toiimg.com",
      "bcclepaper.indiatimes.com",
      "bengali.timesxp.com",
      "biotech.economictimes.indiatimes.com",
      "buy.indiatimes.com",
      "chemicals.economictimes.indiatimes.com",
      "climate.economictimes.indiatimes.com",
      "crypto.economictimes.indiatimes.com",
      "devices.economictimes.indiatimes.com",
      "drones.economictimes.indiatimes.com",
      "economictimes.indiatimes.com",
      "epaper.indiatimes.com",
      "equity.economictimes.indiatimes.com",
      "esports.economictimes.indiatimes.com",
      "et-infographics.indiatimes.com",
      "etcrypto.indiatimes.com",
      "etnonlist.indiatimes.com",
      "etportfolio.indiatimes.com",
      "etpwaapi.economictimes.com",
      "etsearch.indiatimes.com",
      "etsignals.ai",
      "etsub3.indiatimes.com",
      "food.economictimes.indiatimes.com",
      "gadgetsnow.indiatimes.com",
      "geoapi.indiatimes.com",
      "hindi.speakingtree.in",
      "hindi.timesxp.com",
      "hub.etsignals.ai",
      "iamgujarat.com",
      "img.etimg.com",
      "jewellery.economictimes.indiatimes.com",
      "json.bselivefeeds.indiatimes.com",
      "luxury.economictimes.indiatimes.com",
      "m.economictimes.com",
      "m.navbharattimes.indiatimes.com",
      "m.photos.timesofindia.com",
      "m.recipes.timesofindia.com",
      "m.timesofindia.com",
      "maharashtratimes.com",
      "malayalam.samayam.com",
      "marathi.indiatimes.com",
      "marathi.timesxp.com",
      "marketgraphs5.economictimes.indiatimes.com",
      "metaverse.economictimes.indiatimes.com",
      "mfapps.indiatimes.com",
      "mobilelivefeeds.indiatimes.com",
      "mobility.economictimes.indiatimes.com",
      "mumbaimirror.indiatimes.com",
      "navbharattimes.com",
      "navbharattimes.indiatimes.com",
      "nbtbselivefeeds.indiatimes.com",
      "pffeeds.indiatimes.com",
      "photogallery.indiatimes.com",
      "pregatips.in",
      "preprod-reserve.timesblack.com",
      "productmanagement.economictimes.indiatimes.com",
      "recipes.timesofindia.com",
      "recycle.economictimes.indiatimes.com",
      "resources.economictimes.com",
      "robotics.economictimes.indiatimes.com",
      "security.economictimes.indiatimes.com",
      "sme.economictimes.indiatimes.com",
      "spatial.economictimes.indiatimes.com",
      "startups.economictimes.indiatimes.com",
      "static.toiimg.com",
      "steel.economictimes.indiatimes.com",
      "stockreports.economictimes.com",
      "stockreports.economictimes.indiatimes.com",
      "tamil.samayam.com",
      "tamil.timesxp.com",
      "telugu.samayam.com",
      "telugu.timesxp.com",
      "timeshealthplus.com",
      "timeslanguages.in",
      "timesofindia.indiatimes.com",
      "timexp.co.in",
      "trade.economictimes.indiatimes.com",
      "upskill.indiatimes.com",
      "vijaykarnataka.com",
      "whatshot.in",
      "widget.economictimes.indiatimes.com",
      "www.1838reserve.com",
      "www.etsignals.ai",
      "www.hub.etsignals.ai",
      "www.iamgujarat.com",
      "www.indiatimes.com",
      "www.mobilevk.com",
      "www.navbharattimes.com",
      "www.navbharattimes.indiatimes.com",
      "www.pregatips.in",
      "www.preprod-reserve.timesblack.com",
      "www.timeshealthplus.com",
      "www.timeslanguages.in",
      "www.whatshot.in"
    ],
    "days_left": 59,
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
    "title": "Business News Live, Share Market News - Read Latest Finance News, IPO, Mutual Funds News - The Economic Times"
  },
  "mixed_content": [
    "href=\"http://"
  ],
  "cookies": [
    {}
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.economictimes.indiatimes.com",
      "acao": "https://sub.economictimes.indiatimes.com",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://economictimes.indiatimes.com/"
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
    "/api/": 308
  },
  "subdomains": {
    "source": "certspotter",
    "count": 245,
    "notable": [
      "api.economictimes.indiatimes.com",
      "apps.economictimes.indiatimes.com",
      "hr.economictimes.indiatimes.com",
      "img.economictimes.indiatimes.com",
      "payment.economictimes.indiatimes.com",
      "static.economictimes.indiatimes.com",
      "www.hr.economictimes.indiatimes.com",
      "www.infra.economictimes.indiatimes.com"
    ],
    "sample": [
      "adcontrol.economictimes.indiatimes.com",
      "agriculture-stage.economictimes.indiatimes.com",
      "ai-preprod.economictimes.indiatimes.com",
      "ai.economictimes.indiatimes.com",
      "alerts.economictimes.indiatimes.com",
      "api-preprod.economictimes.indiatimes.com",
      "api.economictimes.indiatimes.com",
      "apps.economictimes.indiatimes.com",
      "ask.economictimes.indiatimes.com",
      "auto-preprod.economictimes.indiatimes.com",
      "auto-qa.economictimes.indiatimes.com",
      "auto-stage.economictimes.indiatimes.com",
      "auto.economictimes.indiatimes.com",
      "aviation-stage.economictimes.indiatimes.com",
      "aviation.economictimes.indiatimes.com",
      "b2b-api.economictimes.indiatimes.com",
      "b2b-jcms-api.economictimes.indiatimes.com",
      "b2b-preprod.economictimes.indiatimes.com",
      "b2badmin.economictimes.indiatimes.com",
      "b2bapi.economictimes.indiatimes.com"
    ],
    "dangling": [
      "img.economictimes.indiatimes.com"
    ]
  },
  "cname_chain": [
    "economictimes.indiatimes.com-v1.edgekey.net",
    "e180620.dscj.akamaiedge.net"
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
      "not_before": "20260827045323",
      "not_after": "20261125045322"
    }
  },
  "http2": {
    "robots_disallow": [
      "/PDAET/",
      "/7176/",
      "*/notify.htm?*",
      "/default1.cms",
      "/default.cms",
      "/*rssarticleshow*",
      "/*cms.dll*",
      "/*/opinions/",
      "/pmcomment/",
      "/logtopickeywords.cms",
      "/logtopickeywords.cms?query=",
      "/researchview.cms?searchid=",
      "/researchviewcomm.cms?searchid=",
      "/articleshow_cmtofartac/",
      "/cmtofart/"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "a104-116-243-96.deploy.static.akamaitechnologies.com."
    ]
  },
  "elapsed_s": 8.7,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
