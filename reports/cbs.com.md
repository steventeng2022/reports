# Security Audit Report — cbs.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cbs.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | cbs.com |
| Test date | 2026-09-26 18:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 4, Info: 15)

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
- **Detail:** Apex TXT records with verification/token content: cursor-domain-verification-w3k7jb=Mmgep5pBpOeN01mmeuk7k9UM8; edisen-verification-key=8f029dc6-1fd2-4bdc-8ee5-073a334f3eaa; mongodb-site-verification=zKDU5qGhEc0p64kdgWDPRGB2iIDxJsH9
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
- **Detail:** 3.126.5.188 carries PTR ec2-3-126-5-188.eu-central-1.compute.amazonaws.com. for cbs.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "cbs.com",
  "dns": {
    "a": [
      "3.126.5.188",
      "18.185.24.46",
      "3.71.139.153"
    ],
    "aaaa": [
      "2a05:d014:803:f30c:505c:9738:13c:b7a5",
      "2a05:d014:803:f30e:ffe5:90d1:736a:fcad",
      "2a05:d014:803:f30a:4c8d:5530:dac2:179"
    ],
    "cname": null,
    "mx": [
      "mxa-00262c01.gslb.pphosted.com (pref 0)",
      "mx0a-00262c01.pphosted.com (pref 20)",
      "mx0b-00262c01.pphosted.com (pref 20)",
      "mxb-00262c01.gslb.pphosted.com (pref 0)"
    ],
    "ns": [
      "dns2.p09.nsone.net.",
      "dns3.p09.nsone.net.",
      "dns4.p09.nsone.net.",
      "ns0243.secondary.cloudflare.com.",
      "ns0004.secondary.cloudflare.com.",
      "dns1.p09.nsone.net."
    ],
    "spf": [
      "cursor-domain-verification-w3k7jb=Mmgep5pBpOeN01mmeuk7k9UM8",
      "edisen-verification-key=8f029dc6-1fd2-4bdc-8ee5-073a334f3eaa",
      "MS=ms19625380",
      "9c2e4682d62e4bc1b83fd096b19b4133",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ip4:170.20.0.0/16 ip4:192.238.125.248/29 ip4:192.238.127.124/30 ip4:192.238.95.12/31 ip4:198.99.118.0/23 ip4:216.239.112.0/20 ip4:64.30.227.218 ip4:64.30.231.0/25 ip4:74.125.148.0/22 ip4:66.171.202.1/32 ",
      "ip4:199.85.116.25 ip4:52.5.134.202 ip4:192.238.95.141/27 include:spf.protection.outlook.com include:_spf.google.com include:_netblocks.viacom.com include:_spf.salesforce.com include:spf-00262c02.pphosted.com include:smtp.app.echomark.com -all",
      "mongodb-site-verification=zKDU5qGhEc0p64kdgWDPRGB2iIDxJsH9",
      "elevenlabs=oLxS0_BBKCrkY4U1UA2b2CNL58srDC1eIcrGISL79RE",
      "smartsheet-site-validation=fi4r0takqwh-EHcjb-CZhZvYoRBBKQ2-",
      "echomark-domain-verification=019e8f4f-f967-77ed-874a-842c7c126b7f",
      "I4PDudah320pFzRklVfDTkn9SIJHO4WKPRz7RsrLwWtjGL4Vqc78gFXDisko2giT3g+QTwfvYb4cPZy/jA08fQ==",
      "smartsheet-site-validation=nOrfn3FHZ5ADEze-eJlaIFva5NEYK4HJ",
      "ahrefs-site-verification_a090368a0301a92f7320d0221998037d0a4585cfac2ea7f19842b55baa01a9e9",
      "jumpdesktop=b4fa936a2391b2c031678520a28921add6f4a4ac3124925307ed23a5d0cd",
      "jamf-site-verification=a3Fj5VQCdAtGX43rqyj1mQ",
      "docker-verification=998fe766-03cd-4edd-89ec-686a9bdb8ffd",
      "MS=ms68193247",
      "google-site-verification:jycEA9SnsRqxr4yRvO178BZVLPhGVMXGjrjjmiIxaWs",
      "MS=ms33190795",
      "Dynatrace-site-verification=2c825a10-c7d2-4d0d-ad9d-b3a297b87389__garjptoag7b57591ii5ijf34j0",
      "06lbvwmgw17v9lcjddt2xv8krnby1sy7",
      "lucidlink-verification=P7RCNP9VTRT2SYJ78H5HNG7W9M",
      "elevenlabs=H5kuOqr8fZrhkFwf4r_Yujuxp6wI5N_aiKWp1i0QbN4",
      "_globalsign-domain-verification=KRYUAaIdI2Hm0sL3et24xMRZ1Z04xSIOipNqTFowDv",
      "atlassian-domain-verification=naOIwEMBtdvHkw+IbFFLC3NjVyvxpx+lz8FkxRTnOkMNCka9n9vgGV7HxruWh4Rf",
      "apple-domain-verification=8eUiChfwCLb5sgRU",
      "mongodb-site-verification=Da5cIXJAed1ruJ6eaJM8TZbPwjpOBZNk",
      "apple-domain-verification=JCjy3KA3JizlAuxJ",
      "fastly_delegation-x6tUm3FMIioXHPmJtUf4-356335-2021-0325",
      "wombat-verification=3KwxVCQV1HEp-aRXRTKKaZ5G0frhk",
      "parallels-domain-verification=19f7e985539e42cca485ea9a8dc3dd94c6f9931d85d8423b8ecef69756834710",
      "flexera-domain-verification-llinghxwqvjodvhz",
      "google-site-verification=ZH9b78AnoW-I4pg9tjWF2lKKfA0Dyqwm3p_SOGuSJo4",
      "zapier-domain-verification-challenge=182a380e-d8cb-48d0-8e86-3415469bd188",
      "smartsheet-site-validation=6fRfOip63D5bQxcxIgBuQ3nnkqKfkSL_",
      "anthropic-domain-verification-gza3ps=IbXgCu5n0ntv2zdI90Lo0PxMQ",
      "mongodb-site-verification=T62Bm0WB86kaJUIZ4oCf0K3y7fjhW1LH",
      "google-site-verification=ZTM_XBqlJiw5v4mkB2Uk8luIp85S8Tk3rr6-xe3gJ4w",
      "adobe-idp-site-verification=9b12eeee86b1217caefd9bbbc36da8e767b6c0cca5d2d3bf31c4e295edfa77a0",
      "Fastly-Verify-s8dk39din4n5jajsd8",
      "adobe-sign-verification=68cebdbe443dcb16df9d0a70159ea1b4",
      "onetrust-domain-verification=40c996e736cc495ca304800c7d770182",
      "wiz-domain-verification=6fd13e7cdaff683d7d119656d141ce4e9caeec911c829518efb28e9acbf43323",
      "docusign=386b0618-baa0-4cdb-9a7f-8ab02ec40558",
      "90cdadc0e313448e9e53b744f2a8bcb7",
      "MS=ms66906550",
      "_9wqjcd0f9p5hunqt2p6enolap3ckxbv",
      "mongodb-site-verification=WFelJyPKc7eyMd0LDavgsUk4sVH0TLPA",
      "openai-domain-verification=dv-r9tHTSsnvIsv2rnpBDBWwgYk",
      "openai-domain-verification=dv-cT9qwiInKClYkXoNTBhyJuzU",
      "atlassian-domain-verification=E+wiTTQbdi+aIBlOe7MvMyDmxBdCed/oDG6hRZquh5QIu+JegSoM3VH8Fof+kOz6",
      "458111aa584c42ff93f3847e07351879",
      "google-site-verification=wfRkqvYvkuHwHrdobgtemVB0CnFS2hXVus5ht3LAT3o",
      "appspace-domain-verification=95717daa24b5c09519b505de173a1b8d2d0d37ec64cb70ce7d6fde2847c72bca",
      "onetrust-domain-verification=61d8a6aba17340b3b5f0101aeae999eb"
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
    "days_left": 71,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.126.5.188",
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
    "cursor-domain-verification-w3k7jb=Mmgep5pBpOeN01mmeuk7k9UM8",
    "edisen-verification-key=8f029dc6-1fd2-4bdc-8ee5-073a334f3eaa",
    "mongodb-site-verification=zKDU5qGhEc0p64kdgWDPRGB2iIDxJsH9",
    "echomark-domain-verification=019e8f4f-f967-77ed-874a-842c7c126b7f",
    "ahrefs-site-verification_a090368a0301a92f7320d0221998037d0a4585cfac2ea7f19842b55"
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
      "ec2-3-126-5-188.eu-central-1.compute.amazonaws.com."
    ]
  },
  "elapsed_s": 28.0,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
