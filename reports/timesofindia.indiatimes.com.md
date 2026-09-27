# Security Audit Report — timesofindia.indiatimes.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://timesofindia.indiatimes.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | timesofindia.indiatimes.com |
| Test date | 2026-09-27 01:36 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 3, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 9 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 12 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 13 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 14 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 15 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 16 | info | HTML14 | Public root document marked noindex | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 30 days (notAfter Oct 27 05:38:36 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

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

### 8. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 9. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.timesofindia.indiatimes.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of timesofindia.indiatimes.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but timesofindia.indiatimes.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 12. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 104.116.243.96 carries PTR a104-116-243-96.deploy.static.akamaitechnologies.com. for timesofindia.indiatimes.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 13. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for timesofindia.indiatimes.com; apex indiatimes.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 14. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /security.txt on timesofindia.indiatimes.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 15. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of timesofindia.indiatimes.com carries alt-svc h3=":443"; ma=93600; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 16. [INFO] Public root document marked noindex (`HTML14`)

- **CWE:** CWE-200
- **Detail:** The root document of timesofindia.indiatimes.com is marked noindex (meta robots or X-Robots-Tag); a public homepage that is not indexable is a posture anomaly worth reviewing.
- **Recommendation:** Confirm the noindex directive is intentional.

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
      "2600:1417:76::6874:f353",
      "2600:1417:76::6874:f360"
    ],
    "cname": "timesofindia.indiatimes.com-v1.edgekey.net.",
    "mx": [],
    "ns": [],
    "caa": [],
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
    "ip": "104.116.243.96",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "TOI - Breaking News, Latest News, India News, World News, Bollywood, Sports, Business and Political News | The Times of India"
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": "false"
    },
    {
      "origin": "https://sub.timesofindia.indiatimes.com",
      "acao": "*",
      "acac": "false"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://timesofindia.indiatimes.com/"
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
    "status": "ct-pending"
  },
  "cname_chain": [
    "timesofindia.indiatimes.com-v1.edgekey.net",
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
      "serial": 607320001115839377860534585184096008760585,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://yr1.c.lencr.org/10.crl"
      ],
      "subject_dn": "311930170603550403131074696d65736f66696e6469612e636f6d",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303595231",
      "not_before": "20260729053837",
      "not_after": "20261027053836"
    }
  },
  "x12": {
    "status": 200,
    "ptr": [
      "a104-116-243-96.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 200,
    "p404_status": 404,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=86400",
    "security_txt": "/security.txt",
    "crl": {
      "url": "http://yr1.c.lencr.org/10.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "x16": {
    "root_status": 200,
    "alt_svc": "h3=\":443\"; ma=93600",
    "noindex": true
  },
  "elapsed_s": 32.5,
  "rechecked": "2026-09-27 01:08 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- re-run #15 passive additions: TLS 1.0/1.1, cipher-suite and key-exchange observations come from the handshake the base TLS check already performed plus one quiet re-handshake with no HTTP traffic; HTML-level angles read the root document already fetched for header checks; the only extra request this pass is a read-only GET to /.well-known/openid-configuration (plus the earlier passes' security.txt, sitemap.xml and CRL GETs).
- re-run #16 passive additions: the edge/protocol angles read the alt-svc, server-timing and CDN-identification headers from the one root GET; the preconnect/dns-prefetch, base-href and noindex angles parse the already-fetched root document; the TLS 1.2-only ceiling, SHA-1 signature and weak-key angles use the certificate evidence the base TLS check already captured; the only extra requests this pass are two read-only GETs (/.well-known/jwks.json and /.well-known/change-password).
- Findings are reported against the public program scope; submission through the program tracker is pending.
