# Security Audit Report — ikea.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ikea.com/ |
| Bug bounty program | IKEA |
| Listed scope domain | ikea.com |
| Test date | 2026-09-27 00:22 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 6, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | CT1 | 93 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 19 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.13.173:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.13.173:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 11. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.ikea.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: openai-domain-verification=dv-ruk8aBZomN7tKPUudFE6f4xB; pendo-domain-verification=kNv_0V-tt2G-fFDGQQ35qbcUUIk; adobe-sign-verification=cedca323afb86422862e301984996075
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of ikea.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 93 disallow path(s), e.g. /, */search/?q=*, */search/products/?q=*, */search/content/?q=*, */search/?category=*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] 93 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.food.inter.ikea.com, api.inter.ikea.com, cloud.ap-northeast-2.api.homesmart.ikea.com, cloud.ap-southeast-2.api.homesmart.ikea.com, cloud.api.homesmart.ikea.com, cloud.eu-central-1.api.homesmart.ikea.com, cloud.eu-west-1.api.homesmart.ikea.com, cloud.us-east-1.api.homesmart.ikea.com, history.api.homesmart.ikea.com, hub01.api.ikea.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 19. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: api.inter.ikea.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "ikea.com",
  "dns": {
    "a": [
      "104.18.13.173",
      "104.18.12.173"
    ],
    "aaaa": [
      "2606:4700::6812:dad",
      "2606:4700::6812:cad"
    ],
    "cname": null,
    "mx": [
      "ikea-com.i-v1.mx.microsoft (pref 0)"
    ],
    "ns": [
      "udns2.cscdns.uk.",
      "udns1.cscdns.net."
    ],
    "caa": [
      "0 issue \"pki.goog\"",
      "0 issuewild \"pki.goog\"",
      "0 iodef \"mailto:caa@inter.IKEA.com\"",
      "0 issuewild \"letsencrypt.org\"",
      "0 issue \"awstrust.com\"",
      "0 issue \"amazontrust.com\"",
      "0 issuewild \"digicert.com\"",
      "0 issuewild \"amazonaws.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"sectigo.com\"",
      "0 issuewild \"amazon.com\"",
      "0 issuewild \"awstrust.com\"",
      "0 issuewild \"globalsign.com\"",
      "0 issue \"amazonaws.com\"",
      "0 issue \"amazon.com\"",
      "0 issue \"digicert.com\"",
      "0 issuewild \"sectigo.com\"",
      "0 issuewild \"amazontrust.com\"",
      "0 issue \"globalsign.com\""
    ],
    "spf": [
      "openai-domain-verification=dv-ruk8aBZomN7tKPUudFE6f4xB",
      "pendo-domain-verification=kNv_0V-tt2G-fFDGQQ35qbcUUIk",
      "schrgk1ftng0xtbk5hzdm37z1qm50c5x",
      "ibmid= 402dfd6a-c923-4b4b-8b0b-d48321ad0c03",
      "v=spf1 include:_spf.ikea.com include:spf.protection.outlook.com -all",
      "_0ydey5x097gtj2z92fc6xf342jhw8bm",
      "pwr1x9yqrt58dp5q97xdqc2tjvbfdpfv",
      "adobe-sign-verification=cedca323afb86422862e301984996075",
      "verification=4b7a9cf113659b548dd81c74867cc6e8cdb666dcdedd89006a4b6df841436db9",
      "google-site-verification=snjavwy-fZltgk9KvcOEe73VKX2FVg7YbdH1_GDU9iY",
      "apple-domain-verification=lcR3r6mOMUXCfIBeISYyewJZUPc9Z7njjsCWH3wMJTU",
      "yf27ml09h67l135bgfj8r7k8l06ct0b0",
      "r9l0gn0j4tfvikcnfsoabna4he",
      "google-site-verification=6HRUbiMS72DqS9m1xZA7e2lERsd76qlRP3wjZdbrrr4",
      "openai-domain-verification=dv-NuhNTz6e8ZuA6QC8JPuNWQVI",
      "bc3r1bhgiiv5glji4a4e5q7feq",
      "google-site-verification=eJkdNhxbvSwwMjpJCul26vIgWgojR_DQtUXD9CZMXZY",
      "ecostruxure-it-verification=aed1c019-11ed-4ef4-985a-9d57e6880300",
      "ad44n1huq06eqo04mlhp525gs8",
      "apple-domain-verification=z2IPRZRTU1JvIXzc",
      "c1uaul3js4qk63pu2rlbbipukl",
      "_0f5qdsfyf94runrfkk8kj91gwjunhv1",
      "google-site-verification=E6gWPPnFbnlfZhWvziCK1jbFr7ovdO740_nfJIsM26g",
      "9gk35lcm87nrdcur8l5jc95ffg",
      "airtable-verification=1a7ed489e90d747183dc48f953dc38e2",
      "google-site-verification=5BcCWPMkzRJlhB6Kj1oxpQD-XIiBf1I4axz_YKZhPt8",
      "1gsbjx5k4dg72szsrycjtvbjdxnz7f9w",
      "c7w8ywlzkqtsjrj37zwx3rls92xtg2v2",
      "vuc9hf2qrdsa1rht6jbsvlmm63",
      "ipimblog.azurewebsites.net"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua@ikea.com; ruf=mailto:dmarc_ruf@ikea.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=ikea.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 23 00:30:12 2026 GMT",
    "notAfter": "Dec 22 01:30:11 2026 GMT",
    "san": [
      "ikea.com"
    ],
    "days_left": 86,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.13.173",
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
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.ikea.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.ikea.com/"
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
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 93,
    "notable": [
      "api.food.inter.ikea.com",
      "api.inter.ikea.com",
      "cloud.ap-northeast-2.api.homesmart.ikea.com",
      "cloud.ap-southeast-2.api.homesmart.ikea.com",
      "cloud.api.homesmart.ikea.com",
      "cloud.eu-central-1.api.homesmart.ikea.com",
      "cloud.eu-west-1.api.homesmart.ikea.com",
      "cloud.us-east-1.api.homesmart.ikea.com",
      "history.api.homesmart.ikea.com",
      "hub01.api.ikea.com",
      "m2m-cloud.api.homesmart.ikea.com",
      "m2m-cloud.eu-central-1.api.homesmart.ikea.com",
      "ross-eu-cte.ids.api.inter.ikea.com",
      "ross-eu-dev.ids.api.inter.ikea.com",
      "test.publications.ikea.com"
    ],
    "sample": [
      "ap-northeast-1.iot.homesmart.ikea.com",
      "ap-northeast-2.iot.homesmart.ikea.com",
      "ap-south-1.iot.homesmart.ikea.com",
      "ap-southeast-1.iot.homesmart.ikea.com",
      "ap-southeast-2.iot.homesmart.ikea.com",
      "api.food.inter.ikea.com",
      "api.inter.ikea.com",
      "at-de.publications.ikea.com",
      "ca-central-1.iot.homesmart.ikea.com",
      "cloud.ap-northeast-2.api.homesmart.ikea.com",
      "cloud.ap-southeast-2.api.homesmart.ikea.com",
      "cloud.api.homesmart.ikea.com",
      "cloud.eu-central-1.api.homesmart.ikea.com",
      "cloud.eu-west-1.api.homesmart.ikea.com",
      "cloud.us-east-1.api.homesmart.ikea.com",
      "es-ca.publications.ikea.com",
      "es-en.publications.ikea.com",
      "es-es.publications.ikea.com",
      "es-eu.publications.ikea.com",
      "es-gl.publications.ikea.com"
    ],
    "dangling": [
      "api.inter.ikea.com"
    ]
  },
  "apex_txt": [
    "openai-domain-verification=dv-ruk8aBZomN7tKPUudFE6f4xB",
    "pendo-domain-verification=kNv_0V-tt2G-fFDGQQ35qbcUUIk",
    "adobe-sign-verification=cedca323afb86422862e301984996075",
    "verification=4b7a9cf113659b548dd81c74867cc6e8cdb666dcdedd89006a4b6df841436db9",
    "google-site-verification=snjavwy-fZltgk9KvcOEe73VKX2FVg7YbdH1_GDU9iY"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "serial": 171538633335696715440132310361679054425,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/we1/uKC-4RekmUY.crl"
      ],
      "subject_dn": "3111300f06035504031308696b65612e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531",
      "not_before": "20260923003012",
      "not_after": "20261222013011"
    }
  },
  "http2": {
    "robots_disallow": [
      "/",
      "*/search/?q=*",
      "*/search/products/?q=*",
      "*/search/content/?q=*",
      "*/search/?category=*",
      "*/search/all/?q=*",
      "/compare*",
      "*?filter=*",
      "*?priceFilter*",
      "*?sorting=*",
      "*&sorting=*",
      "*?storeId=*",
      "/catalog/packagepopup/",
      "/iows/",
      "*OrderItemDisplay*"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.ikea.com/",
    "http_status": 301,
    "p404_status": 301,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "crl": {
      "url": "http://c.pki.goog/we1/uKC-4RekmUY.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "elapsed_s": 7.9,
  "rechecked": "2026-09-27 00:08 UTC"
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
- Findings are reported against the public program scope; submission through the program tracker is pending.
