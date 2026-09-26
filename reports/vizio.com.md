# Security Audit Report — vizio.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vizio.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | vizio.com |
| Test date | 2026-09-26 17:54 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 5, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 15 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 16 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 17 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 18 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 19 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 20 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 21 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.147.230:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.147.230:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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

### 14. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 15. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): us., eu. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 16. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 17. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 18. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: adobe-idp-site-verification=d550607d3a8016fc4d439fbbd9554d8b20c4e93b910d512f2886; atlassian-domain-verification=17YsRTCW5OgjY50UTjvUzS5yB2zYstwQvTPYvAfBybjwlALKwa; h1-domain-verification=QrQVudXvTba4t1d1GeBBf1UAtQckKbc1gZ44HSCxLZSGNujs
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 19. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of vizio.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 20. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but vizio.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 21. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 2 disallow path(s), e.g. /setup/verify-email, /*?token=*
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "vizio.com",
  "dns": {
    "a": [
      "104.16.147.230",
      "104.16.146.230"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "us-smtp-inbound-2.mimecast.com (pref 10)",
      "us-smtp-inbound-1.mimecast.com (pref 10)"
    ],
    "ns": [
      "ns13.dnsmadeeasy.com.",
      "ns14.dnsmadeeasy.com.",
      "ns11.dnsmadeeasy.com.",
      "ns10.dnsmadeeasy.com.",
      "ns12.dnsmadeeasy.com.",
      "ns15.dnsmadeeasy.com."
    ],
    "spf": [
      "adobe-idp-site-verification=d550607d3a8016fc4d439fbbd9554d8b20c4e93b910d512f2886144ad0d583e1",
      "atlassian-domain-verification=17YsRTCW5OgjY50UTjvUzS5yB2zYstwQvTPYvAfBybjwlALKwaslA3zcRdJsLmYZ",
      "h1-domain-verification=QrQVudXvTba4t1d1GeBBf1UAtQckKbc1gZ44HSCxLZSGNujs",
      "pexip-ms-tenant-domain-verification=38ff6049-ff44-411c-b07b-2de955c0c85b",
      "smkv6alkgpqb49cmc3t6ovqjo9",
      "vq44bbnnbkhhdg318d31953avp",
      "docusign=5510c0ad-57c4-46c6-8f16-cbfc11c28ea2",
      "onetrust-domain-verification=b2b29ab6ede545c3bc480d80d8a45fbd",
      "cloudflare_dashboard_sso=0ea47d0dc4a12977f61420b61fd0efc0",
      "54haav4tor1tflsikqp6l6ja8j",
      "wrike-verification=MzIzODA2MjozNGQ3NDljMjg3MzJhNDY2ZDNkYmE5OWZmYjYyZWQ0NWYwNzVkN2RhOWU3NWJhMDNhZmE2NThmYmI4Y2Y4NDY2",
      "s5c6b19t2kbipfrji2or82p1hp",
      "google-site-verification=yc51ygPOc_O2Z06G4lUlu36vwR86p3VC9R6-zqMIlv0",
      "4n9odejbrjpju7lq1ffb3fc9pg",
      "docker-verification=50eb7bbd-6572-4e35-8af6-9f2954b30f07",
      "LeSkRBvk4eZKuXOLLeTzlS+pbn/peUbo9rxL1bwK5vpxVp2iwws3w+U0YqJ8EGbGTHI9HBSz233r4HA6w0zWgQ==",
      "l6f79sid1oikoh2713vbm6fgc5",
      "MS=ms58453379",
      "opn8oepgvgpmbet97fmjdg1jo3",
      "506kaaugnfk5036le7j0r1uju0",
      "asv=2a5057615922d022669835607c0f99b0",
      "sprout-social-f848beea-9aa4-40e0-9ed6-ee7bc6b5b6f4",
      "postman-domain-verification=1e263948dab351bb6d0a03ab6e64160f20e59a62b9182b4387a09298c22642ae10c8591d575368d6f180e7f02869cfe3fe080efd8ee529215c725cdbd89b70ae",
      "u904041.wl042.sendgrid.net",
      "asv=10065fd2bf22ce8e2af4ceeb61277df7",
      "onetrust-domain-verification=e2f0baa5a6624a3ea13c4e3f085d69c9",
      "ljkgtvjs8i86ckn43mqeqpgpl0",
      "o2l3darokjtcld5jkdbiqa7jjn",
      "3b5020bb891119b9f5130f1fea9bd773",
      "17YsRTCW5OgjY50UTjvUzS5yB2zYstwQvTPYvAfBybjwlALKwaslA3zcRdJsLmYZ",
      "papntn9hhc23v3ht2dusftpp75",
      "apple-domain-verification=VdlQ3uQr2aBvTQAW",
      "alm2.domainkey.u904041.wl042.sendgrid.net",
      "_globalsign-domain-verification=fI7VTdcVJrf4xZmLqrT_v2voWzga96o3n7WYlcLJys",
      "v=spf1 mx a include:spf.protection.outlook.com include:_spf.salesforce.com include:us._netblocks.mimecast.com include:eu._netblocks.mimecast.com include:8555612.spf04.hubspotemail.net ip4:54.240.67.67 ip4:103.13.69.0/24 ip4:124.47.150.0/24 ip4:124.47.189.",
      "0/24 ip4:103.96.23.0/24 ip4:103.96.21.0/24 ip4:180.189.28.0/24 ip4:216.145.217.0/24 ip4:103.96.22.96/28 ip4:34.208.175.122 ip4:34.215.113.156 ip4:3.20.182.169 ip4:3.101.44.112 ip4:205.201.128.0/20 ip4:198.2.128.0/18 ip4:148.105.0.0/16 ip4:51.163.158.0/24 ",
      "ip4:194.104.109.0/24 ip4:194.104.111.0/24 ip4:51.163.159.21/32 ip4:194.104.110.21/32 ip4:194.104.110.240/28 ip4:62.140.10.21/32 ip4:62.140.7.0/24 ip4:41.74.192.0/22 ip4:41.74.200.0/23 ip4:41.74.196.0/22 ip4:41.74.204.0/23 ip4:41.74.206.0/24 ip4:198.21.6.1",
      "13 ip4:168.245.40.179 ip4:207.38.28.92 ip4:149.72.231.47 ip4:149.72.196.66 -all",
      "jo04mjg3tj3q3st6p1luoh2oqp",
      "k4bZ6C1ju8t+sJKqqNRb9nECxjpJRqoSUL2ORe8V62o=",
      "anyscale-domain-verification-zz6kyq=C921L6emF3sQk0GDPyxmHYpJR",
      "twilio-domain-verification=097980f74fc765c142928fc2b5abc6c0",
      "box-domain-verification=dcd21c699c78e767a82300c331a08417dc6388009f44baf8c7df224e570a63cc",
      "mgverify=414b734285ba918ec8fabff3f3e2588a2fc149eaa9802c62b06c19637873ff10",
      "175b5dcc232526be96f4be817048ddde",
      "rmqlpq9bc5ivniki7cqfccqkcf",
      "google-site-verification=pfZFiFTFek-AB5N9KPjp8Dbg3UPiu5nS8-NkE74b6So",
      "q0j9fn9nsnralsemvm7jr75iem",
      "parallels-domain-verification=b30016926ac3403c9baf914442e9b7651484400893cd48b2894f76b52be33b24",
      "jamf-site-verification=LSIb3UuG5DzQHPmHZuXxbg",
      "alm.domainkey.u904041.wl042.sendgrid.net"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:79b8f25ab298576@rep.dmarcanalyzer.com; ruf=mailto:79b8f25ab298576@for.dmarcanalyzer.com; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=vizio.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 11 22:24:59 2026 GMT",
    "notAfter": "Dec 10 23:24:57 2026 GMT",
    "san": [
      "vizio.com"
    ],
    "days_left": 75,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.16.147.230",
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
      "origin": "https://sub.vizio.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://vizio.com/"
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
    "adobe-idp-site-verification=d550607d3a8016fc4d439fbbd9554d8b20c4e93b910d512f2886",
    "atlassian-domain-verification=17YsRTCW5OgjY50UTjvUzS5yB2zYstwQvTPYvAfBybjwlALKwa",
    "h1-domain-verification=QrQVudXvTba4t1d1GeBBf1UAtQckKbc1gZ44HSCxLZSGNujs",
    "pexip-ms-tenant-domain-verification=38ff6049-ff44-411c-b07b-2de955c0c85b",
    "onetrust-domain-verification=b2b29ab6ede545c3bc480d80d8a45fbd"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/setup/verify-email",
      "/*?token=*"
    ]
  },
  "elapsed_s": 5.8,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
