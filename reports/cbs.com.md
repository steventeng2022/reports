# Security Audit Report — cbs.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cbs.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | cbs.com |
| Test date | 2026-09-27 02:21 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 5, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 20 | low | H21 | HSTS does not cover subdomains | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: redirectv2
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 9. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: redirectv2
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: edisen-verification-key=8f029dc6-1fd2-4bdc-8ee5-073a334f3eaa; google-site-verification=ZH9b78AnoW-I4pg9tjWF2lKKfA0Dyqwm3p_SOGuSJo4; echomark-domain-verification=019e8f4f-f967-77ed-874a-842c7c126b7f
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of cbs.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but cbs.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 52 disallow path(s), e.g. /shows/upfront_2015/, /shows/upfront_2015/simulcast/, /sitemap/, /thunder/feeds/, /thunder/player/1_0-backup/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 18.185.24.46 carries PTR ec2-18-185-24-46.eu-central-1.compute.amazonaws.com. for cbs.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 20. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on cbs.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of cbs.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

## Evidence (raw response observations)

```json
{
  "domain": "cbs.com",
  "dns": {
    "a": [
      "18.185.24.46",
      "3.126.5.188",
      "3.71.139.153"
    ],
    "aaaa": [
      "2600:1f18:297:ba24:b508:76de:f4a:df34",
      "2600:1f18:297:ba18:6ddc:5d8f:6053:f003",
      "2600:1f18:297:ba0e:7900:f622:48a8:f266"
    ],
    "cname": null,
    "mx": [
      "mx0a-00262c01.pphosted.com (pref 20)",
      "mxb-00262c01.gslb.pphosted.com (pref 0)",
      "mx0b-00262c01.pphosted.com (pref 20)",
      "mxa-00262c01.gslb.pphosted.com (pref 0)"
    ],
    "ns": [
      "dns1.p09.nsone.net.",
      "dns2.p09.nsone.net.",
      "dns4.p09.nsone.net.",
      "dns3.p09.nsone.net.",
      "ns0243.secondary.cloudflare.com.",
      "ns0004.secondary.cloudflare.com."
    ],
    "caa": [
      "0 issuewild \"trust-provider.com\"",
      "0 issuewild \"sectigo.com\"",
      "0 issuewild \"comodoca.com\"",
      "0 issue \"sectigo.com\"",
      "0 issuewild \"amazon.com\"",
      "0 issue \"comodoca.com\"",
      "0 issue \"amazon.com\"",
      "0 issuewild \"starfieldtech.com\"",
      "0 issuewild \"godaddy.com\"",
      "0 issue \"trust-provider.com\"",
      "0 issuewild \"digicert.com\"",
      "0 issue \"usertrust.com\"",
      "0 issue \"digicert.com\"",
      "0 issue \"starfieldtech.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issuewild \"usertrust.com\"",
      "0 issuewild \"letsencrypt.org\"",
      "0 issue \"godaddy.com\""
    ],
    "spf": [
      "edisen-verification-key=8f029dc6-1fd2-4bdc-8ee5-073a334f3eaa",
      "smartsheet-site-validation=nOrfn3FHZ5ADEze-eJlaIFva5NEYK4HJ",
      "MS=ms68193247",
      "google-site-verification=ZH9b78AnoW-I4pg9tjWF2lKKfA0Dyqwm3p_SOGuSJo4",
      "smartsheet-site-validation=6fRfOip63D5bQxcxIgBuQ3nnkqKfkSL_",
      "echomark-domain-verification=019e8f4f-f967-77ed-874a-842c7c126b7f",
      "wombat-verification=3KwxVCQV1HEp-aRXRTKKaZ5G0frhk",
      "Dynatrace-site-verification=2c825a10-c7d2-4d0d-ad9d-b3a297b87389__garjptoag7b57591ii5ijf34j0",
      "I4PDudah320pFzRklVfDTkn9SIJHO4WKPRz7RsrLwWtjGL4Vqc78gFXDisko2giT3g+QTwfvYb4cPZy/jA08fQ==",
      "anthropic-domain-verification-gza3ps=IbXgCu5n0ntv2zdI90Lo0PxMQ",
      "google-site-verification=ZTM_XBqlJiw5v4mkB2Uk8luIp85S8Tk3rr6-xe3gJ4w",
      "elevenlabs=H5kuOqr8fZrhkFwf4r_Yujuxp6wI5N_aiKWp1i0QbN4",
      "mongodb-site-verification=T62Bm0WB86kaJUIZ4oCf0K3y7fjhW1LH",
      "onetrust-domain-verification=61d8a6aba17340b3b5f0101aeae999eb",
      "atlassian-domain-verification=naOIwEMBtdvHkw+IbFFLC3NjVyvxpx+lz8FkxRTnOkMNCka9n9vgGV7HxruWh4Rf",
      "458111aa584c42ff93f3847e07351879",
      "google-site-verification=wfRkqvYvkuHwHrdobgtemVB0CnFS2hXVus5ht3LAT3o",
      "ahrefs-site-verification_a090368a0301a92f7320d0221998037d0a4585cfac2ea7f19842b55baa01a9e9",
      "parallels-domain-verification=19f7e985539e42cca485ea9a8dc3dd94c6f9931d85d8423b8ecef69756834710",
      "fastly_delegation-x6tUm3FMIioXHPmJtUf4-356335-2021-0325",
      "openai-domain-verification=dv-r9tHTSsnvIsv2rnpBDBWwgYk",
      "google-site-verification:jycEA9SnsRqxr4yRvO178BZVLPhGVMXGjrjjmiIxaWs",
      "_globalsign-domain-verification=KRYUAaIdI2Hm0sL3et24xMRZ1Z04xSIOipNqTFowDv",
      "zapier-domain-verification-challenge=182a380e-d8cb-48d0-8e86-3415469bd188",
      "openai-domain-verification=dv-cT9qwiInKClYkXoNTBhyJuzU",
      "mongodb-site-verification=Da5cIXJAed1ruJ6eaJM8TZbPwjpOBZNk",
      "adobe-sign-verification=68cebdbe443dcb16df9d0a70159ea1b4",
      "mongodb-site-verification=zKDU5qGhEc0p64kdgWDPRGB2iIDxJsH9",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ip4:170.20.0.0/16 ip4:192.238.125.248/29 ip4:192.238.127.124/30 ip4:192.238.95.12/31 ip4:198.99.118.0/23 ip4:216.239.112.0/20 ip4:64.30.227.218 ip4:64.30.231.0/25 ip4:74.125.148.0/22 ip4:66.171.202.1/32 ",
      "ip4:199.85.116.25 ip4:52.5.134.202 ip4:192.238.95.141/27 include:spf.protection.outlook.com include:_spf.google.com include:_netblocks.viacom.com include:_spf.salesforce.com include:spf-00262c02.pphosted.com include:smtp.app.echomark.com -all",
      "docker-verification=998fe766-03cd-4edd-89ec-686a9bdb8ffd",
      "Fastly-Verify-s8dk39din4n5jajsd8",
      "jumpdesktop=b4fa936a2391b2c031678520a28921add6f4a4ac3124925307ed23a5d0cd",
      "onetrust-domain-verification=40c996e736cc495ca304800c7d770182",
      "elevenlabs=oLxS0_BBKCrkY4U1UA2b2CNL58srDC1eIcrGISL79RE",
      "90cdadc0e313448e9e53b744f2a8bcb7",
      "_9wqjcd0f9p5hunqt2p6enolap3ckxbv",
      "MS=ms19625380",
      "9c2e4682d62e4bc1b83fd096b19b4133",
      "jamf-site-verification=a3Fj5VQCdAtGX43rqyj1mQ",
      "docusign=386b0618-baa0-4cdb-9a7f-8ab02ec40558",
      "adobe-idp-site-verification=9b12eeee86b1217caefd9bbbc36da8e767b6c0cca5d2d3bf31c4e295edfa77a0",
      "MS=ms33190795",
      "appspace-domain-verification=95717daa24b5c09519b505de173a1b8d2d0d37ec64cb70ce7d6fde2847c72bca",
      "MS=ms66906550",
      "flexera-domain-verification-llinghxwqvjodvhz",
      "06lbvwmgw17v9lcjddt2xv8krnby1sy7",
      "mongodb-site-verification=WFelJyPKc7eyMd0LDavgsUk4sVH0TLPA",
      "wiz-domain-verification=6fd13e7cdaff683d7d119656d141ce4e9caeec911c829518efb28e9acbf43323",
      "smartsheet-site-validation=fi4r0takqwh-EHcjb-CZhZvYoRBBKQ2-",
      "apple-domain-verification=8eUiChfwCLb5sgRU",
      "cursor-domain-verification-w3k7jb=Mmgep5pBpOeN01mmeuk7k9UM8",
      "atlassian-domain-verification=E+wiTTQbdi+aIBlOe7MvMyDmxBdCed/oDG6hRZquh5QIu+JegSoM3VH8Fof+kOz6",
      "lucidlink-verification=P7RCNP9VTRT2SYJ78H5HNG7W9M",
      "apple-domain-verification=JCjy3KA3JizlAuxJ"
    ],
    "dmarc": [
      "v=DMARC1; p=none; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=cbs.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Sep  8 00:46:33 2026 GMT",
    "notAfter": "Dec  7 00:46:32 2026 GMT",
    "san": [
      "cbs.com"
    ],
    "days_left": 70,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "18.185.24.46",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: redirectv2"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.cbs.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.cbs.com/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "edisen-verification-key=8f029dc6-1fd2-4bdc-8ee5-073a334f3eaa",
    "google-site-verification=ZH9b78AnoW-I4pg9tjWF2lKKfA0Dyqwm3p_SOGuSJo4",
    "echomark-domain-verification=019e8f4f-f967-77ed-874a-842c7c126b7f",
    "wombat-verification=3KwxVCQV1HEp-aRXRTKKaZ5G0frhk",
    "Dynatrace-site-verification=2c825a10-c7d2-4d0d-ad9d-b3a297b87389__garjptoag7b575"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "serial": 444406975187880988078712870976972387836575,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://ye1.c.lencr.org/32.crl"
      ],
      "san": [
        "cbs.com"
      ],
      "subject_dn": "3110300e060355040313076362732e636f6d",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303594531",
      "not_before": "20260908004633",
      "not_after": "20261207004632"
    }
  },
  "http2": {
    "robots_disallow": [
      "/shows/upfront_2015/",
      "/shows/upfront_2015/simulcast/",
      "/sitemap/",
      "/thunder/feeds/",
      "/thunder/player/1_0-backup/",
      "/thunder/player/1_0-bak/",
      "/thunder/player/admin/",
      "/thunder/player/chromeless/",
      "/thunder/player/fms3_5/",
      "/thunder/player/ford/",
      "/thunder/css/",
      "/thunder/include/",
      "/thunder/scripts/",
      "/thunder/swf/",
      "/thunder/partner/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-18-185-24-46.eu-central-1.compute.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.cbs.com/",
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
    "hsts": "max-age=31536000",
    "crl": {
      "url": "http://ye1.c.lencr.org/32.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "x17": {},
  "elapsed_s": 40.9,
  "rechecked": "2026-09-27 02:16 UTC"
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
- re-run #17 passive additions: the retired-header angles (Public-Key-Pins, Expect-CT, X-Permitted-Cross-Domain-Policies, Via, COOP/COEP, Permissions-Policy) read from the one root GET; the wildcard SAN, http:// OCSP and 398-day-cap angles use the certificate evidence the base TLS check already captured (SAN now harvested from the existing DER); the only extra requests this pass are three read-only GETs (/.well-known/dpop-jwks.json, /.well-known/origin-rsa-keys.json, /.well-known/llms.txt).
- Findings are reported against the public program scope; submission through the program tracker is pending.
