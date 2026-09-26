# Security Audit Report — popularmechanics.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://popularmechanics.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | popularmechanics.com |
| Test date | 2026-09-26 23:36 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 4, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 10 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 16 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 19 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443";ma=86400,h3-29=":443";ma=86400,h3-27=":443";ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 9. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'location_data' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 10. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'location_data' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=twOgjzEass2e5I7cd-1TQlMR9dhhBOBVnI-e2P7hSvs; tollbit-domain-verification=ece496246caa370d7f007485c8f75bd2fddff24339ca004233b2; yahoo-verification-key=5xONH6yORwG/7kfa3pYWXykyZGH78hWvc/P+MqxMxhI=
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2026q2 -> http-400
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but popularmechanics.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 34 disallow path(s), e.g. User-agent:, /au/, /cn/, /dk/, /en/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://popularmechanics.com/ carries Cache-Control: max-age=0, must-revalidate, private; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 19. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for popularmechanics.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

## Evidence (raw response observations)

```json
{
  "domain": "popularmechanics.com",
  "dns": {
    "a": [
      "151.101.0.155",
      "151.101.64.155",
      "151.101.192.155",
      "151.101.128.155"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "popularmechanics-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns-1955.awsdns-52.co.uk.",
      "ns-790.awsdns-34.net.",
      "ns-181.awsdns-22.com.",
      "ns-1122.awsdns-12.org."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=twOgjzEass2e5I7cd-1TQlMR9dhhBOBVnI-e2P7hSvs",
      "tollbit-domain-verification=ece496246caa370d7f007485c8f75bd2fddff24339ca004233b2740cc82bada5",
      "yahoo-verification-key=5xONH6yORwG/7kfa3pYWXykyZGH78hWvc/P+MqxMxhI=",
      "9991472f6clc7g866tmn1tbhspnwxcdl",
      "fastly-domain-delegation-tHoPyhjKot-363395-2021-04-28",
      "_globalsign-domain-verification=2wRqY6IrIINLY7B8Qcp-qur9HsiRTO04g4gwsMmFy3",
      "google-site-verification=wcwFYNVQ_gHEG0lRSSOEkrXtuYQ5zNIXFTodmJivqgw",
      "fastly-domain-delegation-LJIHG7If6u5dy45rhtfjyGUKHk-00839260-20260924",
      "facebook-domain-verification=i25ihj6b5eze1xweou34v7znz6k5v9",
      "google-site-verification=98saqo61zkfl_yfZaXKLgLkazlZwpUcMCkqCFEO-O18",
      "BSI91896679786",
      "v=spf1 include:aspmx.sailthru.com include:spf.protection.outlook.com ip4:63.240.19.128/25 ip4:12.182.88.0/25 ip4:12.130.33.128/25 ip4:24.103.50.168/29 ip4:205.220.176.159 ip4:205.220.164.154 ~all",
      "MS=ms37465013"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.bazaar.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2026 Q2",
    "notBefore": "Jun 11 15:07:05 2026 GMT",
    "notAfter": "Dec 27 14:07:05 2026 GMT",
    "san": [
      "*.bazaar.com",
      "*.25ans.jp",
      "*.altaonline.com",
      "*.autoweek.com",
      "*.bestproducts.com",
      "*.bicycling.com",
      "*.bringatrailer.com",
      "*.caranddriver.com",
      "*.cdn.hearstapps.net",
      "*.cosmopolitan.com",
      "*.countryliving.com",
      "*.crfashionbook.com",
      "*.delish.com",
      "*.dev.mediaos.hearst.io",
      "*.drozthegoodlife.com",
      "*.elle.com",
      "*.elledecor.com",
      "*.ellegirl.jp",
      "*.esquire.com",
      "*.fujingaho.jp",
      "*.gearpatrol.com",
      "*.ghsealapplication.com",
      "*.goodhouse.com",
      "*.goodhousekeeping.com",
      "*.h-cdn.co",
      "*.harpersbazaar.com",
      "*.hdmtech.net",
      "*.hdmtools.com",
      "*.hearst.io",
      "*.hearstapps.com",
      "*.hearstapps.net",
      "*.hearstdigitalstudios.com",
      "*.hearstdigitalstudios.net",
      "*.hearstlabs.com",
      "*.hearstmags.com",
      "*.housebeautiful.com",
      "*.menshealth.com",
      "*.myio.id",
      "*.mylo.id",
      "*.oprahdaily.com",
      "*.oprahmag.com",
      "*.popularmechanics.com",
      "*.prevention.com",
      "*.redbookmag.com",
      "*.rnylo.com",
      "*.rnylo.id",
      "*.roadandtrack.com",
      "*.rodalesorganiclife.com",
      "*.rrylo.com",
      "*.rrylo.id",
      "*.runnersworld.com",
      "*.seventeen.com",
      "*.thepioneerwoman.com",
      "*.thepioneerwomancooks.com",
      "*.todays-rewards.com",
      "*.townandcountrymag.com",
      "*.veranda.com",
      "*.womansday.com",
      "*.womenshealthmag.com",
      "25ans.jp",
      "altaonline.com",
      "autoweek.com",
      "bazaar.com",
      "bestproducts.com",
      "bicycling.com",
      "bringatrailer.com",
      "caranddriver.com",
      "cosmopolitan.com",
      "countryliving.com",
      "crfashionbook.com",
      "delish.com",
      "drozthegoodlife.com",
      "elle.com",
      "elledecor.com",
      "ellegirl.jp",
      "esquire.com",
      "fujingaho.jp",
      "gearpatrol.com",
      "ghsealapplication.com",
      "goodhouse.com",
      "goodhousekeeping.com",
      "harpersbazaar.com",
      "hdmtech.net",
      "hearstlabs.com",
      "housebeautiful.com",
      "menshealth.com",
      "myio.id",
      "mylo.id",
      "oprahdaily.com",
      "oprahmag.com",
      "popularmechanics.com",
      "prevention.com",
      "redbookmag.com",
      "rnylo.com",
      "rnylo.id",
      "roadandtrack.com",
      "rodalesorganiclife.com",
      "rrylo.com",
      "rrylo.id",
      "runnersworld.com",
      "seventeen.com",
      "thepioneerwoman.com",
      "thepioneerwomancooks.com",
      "todays-rewards.com",
      "townandcountrymag.com",
      "veranda.com",
      "womansday.com",
      "womenshealthmag.com",
      "hearstlive.co.uk",
      "*.menshealth.it",
      "*.runnersworld.it",
      "menshealth.it",
      "runnersworld.it",
      "*.modernliving.jp",
      "modernliving.jp",
      "*.firstfinds.com",
      "firstfinds.com",
      "*.biography.com",
      "biography.com",
      "*.nationalgeographic.nl",
      "nationalgeographic.nl",
      "*.menshealthtravel.com",
      "menshealthtravel.com",
      "*.jumpstarttaggingsolutions.com",
      "*.richessemag.jp",
      "richessemag.jp",
      "*.hearstmags.id",
      "hearstmags.id",
      "*.nuevoestilo.es",
      "nuevoestilo.es",
      "*.hearstautos.net",
      "*.intelliprice.com",
      "intelliprice.com",
      "*.gente.it",
      "gente.it",
      "*.cdn-test.hearstapps.net",
      "shopbazaar.com",
      "www.shopbazaar.com",
      "*.motortrend.com",
      "motortrend.com",
      "*.hotrod.com",
      "hotrod.com",
      "*.mtg.cdn.hearstapps.net",
      "*.feature.sex.cosmopolitan.com",
      "feature.sex.cosmopolitan.com",
      "stage.sex.cosmopolitan.com",
      "*.hearstaura.com",
      "hearstaura.com"
    ],
    "days_left": 91,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.0.155",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
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
      "origin": "https://sub.popularmechanics.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.popularmechanics.com/"
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
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=twOgjzEass2e5I7cd-1TQlMR9dhhBOBVnI-e2P7hSvs",
    "tollbit-domain-verification=ece496246caa370d7f007485c8f75bd2fddff24339ca004233b2",
    "yahoo-verification-key=5xONH6yORwG/7kfa3pYWXykyZGH78hWvc/P+MqxMxhI=",
    "_globalsign-domain-verification=2wRqY6IrIINLY7B8Qcp-qur9HsiRTO04g4gwsMmFy3",
    "google-site-verification=wcwFYNVQ_gHEG0lRSSOEkrXtuYQ5zNIXFTodmJivqgw"
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
      "aia_ocsp": "http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2026q2",
      "serial": 2352087675201354367370267127462513809,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.globalsign.com/ca/gsatlasr3dvtlsca2026q2.crl"
      ],
      "subject_dn": "3115301306035504030c0c2a2e62617a6161722e636f6d",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312e302c06035504031325476c6f62616c5369676e2041746c617320523320445620544c532043412032303236205132",
      "not_before": "20260611150705",
      "not_after": "20261227140705"
    },
    "ocsp": "http-400"
  },
  "http2": {
    "robots_disallow": [
      "User-agent:",
      "/au/",
      "/cn/",
      "/dk/",
      "/en/",
      "/es/",
      "/in/",
      "/it/",
      "/jp/",
      "/ng/",
      "/nl/",
      "/no/",
      "/se/",
      "/ua/",
      "/uk/"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.popularmechanics.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=31557600; includeSubDomains",
    "crl": {
      "url": "http://crl.globalsign.com/ca/gsatlasr3dvtlsca2026q2.crl",
      "status": 200
    }
  },
  "elapsed_s": 22.0,
  "rechecked": "2026-09-26 23:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- Findings are reported against the public program scope; submission through the program tracker is pending.
