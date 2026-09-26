# Security Audit Report — constantcontact.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://constantcontact.com/ |
| Bug bounty program | Constant Contact |
| Listed scope domain | constantcontact.com |
| Test date | 2026-09-26 17:42 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | low | RED10 | Host header reflected into redirect Location | CWE-601 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Apache
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=S0PJ1RSXkRxVn-okVzPY9Lzeghej1eIywqeTx0o2MKE; duo_sso_verification=7HPXqXi0wOuCX7DdMLeu09LySVwMqymRiBWo3e5f1J9JumDaZTfzYPxfcpn; globalsign-domain-verification=5C905CAD6161760D48FA250433C2EEF9
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of constantcontact.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but constantcontact.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [LOW] Host header reflected into redirect Location (`RED10`)

- **CWE:** CWE-601
- **Detail:** GET with Host: evil-auditor.example -> Location: https://evil-auditor.example/index.jsp
- **Recommendation:** Validate redirect targets against the expected host.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 10 disallow path(s), e.g. /blog/event/?*, /blog/events/?*, /blog/page/*/?s=, /blog/?s=, /blog/search/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "constantcontact.com",
  "dns": {
    "a": [
      "208.75.122.14"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "edgemail1.constantcontact.com (pref 10)",
      "edgemail2.constantcontact.com (pref 20)"
    ],
    "ns": [
      "dns3.p01.nsone.net.",
      "dns1.p01.nsone.net.",
      "dns2.p01.nsone.net.",
      "dns4.p01.nsone.net."
    ],
    "spf": [
      "google-site-verification=S0PJ1RSXkRxVn-okVzPY9Lzeghej1eIywqeTx0o2MKE",
      "docusign=d814c280-26f9-41c7-aa92-a03b59e6fd58",
      "spf2.0/pra ip4:208.75.120.0/22 ip4:205.207.104.0/22 include:_ext.constantcontact.com include:_spf.salesforce.com include:_spf.google.com ~all",
      "MS=ms18093078",
      "duo_sso_verification=7HPXqXi0wOuCX7DdMLeu09LySVwMqymRiBWo3e5f1J9JumDaZTfzYPxfcpnbQCRi",
      "MS=91FCD146A8340927C3F9723C8F3DC44A5AE57414",
      "globalsign-domain-verification=5C905CAD6161760D48FA250433C2EEF9",
      "ps-cd-verification=3e13eeb0-a25b-41af-a9d1-d5c8cca8082a",
      "logmein-verification-code=491874e6-5c3b-4b37-b19e-f523d7d74473",
      "stripe-verification=685340051470B5606798FED265AD82838FDC4D525047AEBAC6F8577B731D91CA",
      "google-site-verification=lMXxJuCIadZI6yIKv7z5_Va70POuM19qU81NU0tmaxI",
      "reachdesk-verification=1CmlRrcJcF7N7kW8ionhhGt21vydYDeiaGjRKoFAJHCsTyxLVFHOcdUBxBeUrt3H",
      "jamf-site-verification=aFdwoWd1sPeHAeoixINgyw",
      "SFMC-nnhzrK01oLNsym2xcDKcUEXUlbm8OIrlrUxoOGdS",
      "atlassian-domain-verification=fMjaVWKHpJhM3aAlDYkNe5/yuAOUIOva2QexA9BN3WIHOkZmfqX9AWdaOicLtJYr",
      "kF4qrcASQQx6dXlhtT5OqM1QkLhxmOFd9TIEk0+L+Hg=.",
      "canva-site-verification=ZyZ5z6fQIoIHCDU_U8K6YQ",
      "google-site-verification=GEYwmfZ7RuvBcI7BT6xQnrNfn1z7gWUKLfVIalnwqeA",
      "meltwater_sso_20260521_triton-36710",
      "anthropic-domain-verification-y2453z=RP4EoX2XlEAObiHw4Qyfxyif2",
      "globalsign-domain-verification=A899C94328AC5076D4198E6055E9C6E1",
      "MS=ms76971383",
      "globalsign-domain-verification=1FF9A93F847B1EB612F7EB378BFA8F2F",
      "pendo-domain-verification=n9rM3WLge63EWPA3kOPW1OUEcXg",
      "cursor-domain-verification-fad4vy=0NZxtFJAF9pFISdFqx3nMzNyk",
      "globalsign-domain-verification=FA2D0568288440FE444CE3BEE2B3FD88",
      "v0IqpOXySDIxu292XtWFBWVQ2T3C/MLnpiy5EKsfKWg=.",
      "openai-domain-verification=dv-tjo2gRJDV0e90MlGZWURanbs",
      "google-site-verification=JtNhbwEnbIVid2N5wO0kF9kJ5jfx_ttYqfleBTqKZJY",
      "google-site-verification=9SlseBmCRNaS8PoCIcXUBYR18HWP6RBX9HyD3R5R5Ls",
      "globalsign-domain-verification=6FFE99D6D65D30A44C49A374C5143D87",
      "google-site-verification=ALoYvB9LP05aK7ddKNWCSrNKI4QPPh647yXxmNq1rJ4",
      "validity-domain-monitoring=lWgicWp5GPvLfdEoFXdAYpMXV",
      "globalsign-domain-verification=C385682A22F86586CCE2465D9544AA1C",
      "ZOOM_verify_lz7Vk7Mf3ZEzuB6jwtCEVv",
      "globalsign-domain-verification=1FF969BDF7F6D9B06243EFA8042CBDE7",
      "facebook-domain-verification=9wo9l62thl595soh1wjzolqfv3ao8c",
      "Cb20W914dVUL9V8ziCkX1Qo",
      "v=spf1 ip4:208.75.120.0/22 ip4:205.207.104.0/22 include:_ext.constantcontact.com include:_spf.salesforce.com include:_spf.google.com ~all",
      "globalsign-domain-verification=F1462C7038793BEEB6A1FCE7B31E06B7",
      "TAILSCALE-WN5I3ZooiwxJsVakFdjs",
      "validate.onetrust-domain-verification=8c431f2bfba744d99f5df0ee4ef55df1",
      "cisco-ci-domain-verification=2bd65a16476143d0aebade20fdf9ca88de20694b28dbd9a7630bd6a72c690a63",
      "google-site-verification=5lHEZKPh-_wYKf6iPhatHRpXj2l0R9NmPQ9wSWIAQag",
      "tgXS6TJ3fVTnME8cpaIfgd9fe2rkAsn8kgSVRi/Af/c=",
      "globalsign-domain-verification=83DF7D9B4CADBA9AB6D6ED1792F009A4",
      "globalsign-domain-verification=607B2BE93D2B60F139751C389A14C13B",
      "globalsign-domain-verification=D5A7AFA31C2BFA6174B52F0F9E90C9DF",
      "google-site-verification=RMx0cdA4nEA6nAg48o0lsv4eb29EbVafa7weQBnSNJQ",
      "google-site-verification=Gp7Hv6yLosjKQ_t7gHJROnXoAYK7wlz1XLOBHt_J7HE"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:tk0syg54@ag.dmarcian.com,mailto:dmarc_agg@vali.email; ruf=mailto:tk0syg54@fr.dmarcian.com; rf=afrf;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=Massachusetts, localityName=Waltham, organizationName=Constant Contact, Inc., commonName=*.constantcontact.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 OV TLS CA 2025 Q4",
    "notBefore": "Nov 10 16:54:48 2025 GMT",
    "notAfter": "Dec 12 16:54:47 2026 GMT",
    "san": [
      "*.constantcontact.com",
      "constantcontact.co.uk",
      "www.constantcontact.co.uk",
      "constantcontact.in",
      "www.constantcontact.in",
      "constantcontactbook.com",
      "www.constantcontactbook.com",
      "constantcontactplaybook.com",
      "www.constantcontactplaybook.com",
      "constantcontact-playbook.com",
      "www.constantcontact-playbook.com",
      "constantcontactsocialplaybook.com",
      "www.constantcontactsocialplaybook.com",
      "constantcontact-socialplaybook.com",
      "www.constantcontact-socialplaybook.com",
      "constantcontactsocialplaybook.co.uk",
      "www.constantcontactsocialplaybook.co.uk",
      "constantcontact-socialplaybook.co.uk",
      "www.constantcontact-socialplaybook.co.uk",
      "smqproject.com",
      "www.smqproject.com",
      "socialmediaquickstarter.com",
      "www.socialmediaquickstarter.com",
      "socialquickstarter.com",
      "www.socialquickstarter.com",
      "ccsend.com",
      "msgexch.com",
      "rs6.net",
      "constantcontact.ca",
      "constantcontact.com.au",
      "constantcontact.au",
      "constantcontact.uk",
      "constantcontact.nz",
      "smbclub.com.au",
      "*.ccsend.com",
      "*.msgexch.com",
      "*.rs6.net",
      "constantcontact.com"
    ],
    "days_left": 76,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "208.75.122.14",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Apache"
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
      "origin": "https://sub.constantcontact.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.constantcontact.com/"
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
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 301,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=S0PJ1RSXkRxVn-okVzPY9Lzeghej1eIywqeTx0o2MKE",
    "duo_sso_verification=7HPXqXi0wOuCX7DdMLeu09LySVwMqymRiBWo3e5f1J9JumDaZTfzYPxfcpn",
    "globalsign-domain-verification=5C905CAD6161760D48FA250433C2EEF9",
    "ps-cd-verification=3e13eeb0-a25b-41af-a9d1-d5c8cca8082a",
    "logmein-verification-code=491874e6-5c3b-4b37-b19e-f523d7d74473"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/blog/event/?*",
      "/blog/events/?*",
      "/blog/page/*/?s=",
      "/blog/?s=",
      "/blog/search/",
      "/blog/search/*",
      "/legal/*",
      "/opt-out.jsp",
      "/opt-out-info.jsp",
      "/pricing.v1.json"
    ]
  },
  "elapsed_s": 29.0,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
