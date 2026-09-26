# Security Audit Report — constantcontact.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://constantcontact.com/ |
| Bug bounty program | Constant Contact |
| Listed scope domain | constantcontact.com |
| Test date | 2026-09-26 23:22 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 5, Info: 17)

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
| 14 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | low | RED10 | Host header reflected into redirect Location | CWE-601 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 19 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 20 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 21 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 22 | low | H21 | HSTS does not cover subdomains | CWE-319 |

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
- **Detail:** Apex TXT records with verification/token content: globalsign-domain-verification=83DF7D9B4CADBA9AB6D6ED1792F009A4; reachdesk-verification=1CmlRrcJcF7N7kW8ionhhGt21vydYDeiaGjRKoFAJHCsTyxLVFHOcdUBx; canva-site-verification=ZyZ5z6fQIoIHCDU_U8K6YQ
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.globalsign.com/ca/gsatlasr3ovtlsca2025q4 -> http-400
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

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

### 18. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://constantcontact.com/ carries Cache-Control: max-age=0; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 19. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 208.75.122.14 carries PTR www.constantcontact.com. for constantcontact.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 20. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for constantcontact.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 21. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The constantcontact.com certificate lists an AIA OCSP responder (http://ocsp.globalsign.com/ca/gsatlasr3ovtlsca2025q4) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 22. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on constantcontact.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of constantcontact.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

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
      "edgemail2.constantcontact.com (pref 20)",
      "edgemail1.constantcontact.com (pref 10)"
    ],
    "ns": [
      "dns4.p01.nsone.net.",
      "dns3.p01.nsone.net.",
      "dns2.p01.nsone.net.",
      "dns1.p01.nsone.net."
    ],
    "caa": [],
    "spf": [
      "validity-domain-monitoring=lWgicWp5GPvLfdEoFXdAYpMXV",
      "globalsign-domain-verification=83DF7D9B4CADBA9AB6D6ED1792F009A4",
      "reachdesk-verification=1CmlRrcJcF7N7kW8ionhhGt21vydYDeiaGjRKoFAJHCsTyxLVFHOcdUBxBeUrt3H",
      "spf2.0/pra ip4:208.75.120.0/22 ip4:205.207.104.0/22 include:_ext.constantcontact.com include:_spf.salesforce.com include:_spf.google.com ~all",
      "canva-site-verification=ZyZ5z6fQIoIHCDU_U8K6YQ",
      "anthropic-domain-verification-y2453z=RP4EoX2XlEAObiHw4Qyfxyif2",
      "stripe-verification=685340051470B5606798FED265AD82838FDC4D525047AEBAC6F8577B731D91CA",
      "globalsign-domain-verification=C385682A22F86586CCE2465D9544AA1C",
      "globalsign-domain-verification=5C905CAD6161760D48FA250433C2EEF9",
      "globalsign-domain-verification=FA2D0568288440FE444CE3BEE2B3FD88",
      "cisco-ci-domain-verification=2bd65a16476143d0aebade20fdf9ca88de20694b28dbd9a7630bd6a72c690a63",
      "google-site-verification=lMXxJuCIadZI6yIKv7z5_Va70POuM19qU81NU0tmaxI",
      "kF4qrcASQQx6dXlhtT5OqM1QkLhxmOFd9TIEk0+L+Hg=.",
      "duo_sso_verification=7HPXqXi0wOuCX7DdMLeu09LySVwMqymRiBWo3e5f1J9JumDaZTfzYPxfcpnbQCRi",
      "facebook-domain-verification=9wo9l62thl595soh1wjzolqfv3ao8c",
      "ZOOM_verify_lz7Vk7Mf3ZEzuB6jwtCEVv",
      "SFMC-nnhzrK01oLNsym2xcDKcUEXUlbm8OIrlrUxoOGdS",
      "docusign=d814c280-26f9-41c7-aa92-a03b59e6fd58",
      "validate.onetrust-domain-verification=8c431f2bfba744d99f5df0ee4ef55df1",
      "google-site-verification=JtNhbwEnbIVid2N5wO0kF9kJ5jfx_ttYqfleBTqKZJY",
      "globalsign-domain-verification=F1462C7038793BEEB6A1FCE7B31E06B7",
      "google-site-verification=RMx0cdA4nEA6nAg48o0lsv4eb29EbVafa7weQBnSNJQ",
      "google-site-verification=S0PJ1RSXkRxVn-okVzPY9Lzeghej1eIywqeTx0o2MKE",
      "openai-domain-verification=dv-tjo2gRJDV0e90MlGZWURanbs",
      "meltwater_sso_20260521_triton-36710",
      "globalsign-domain-verification=D5A7AFA31C2BFA6174B52F0F9E90C9DF",
      "MS=ms76971383",
      "v0IqpOXySDIxu292XtWFBWVQ2T3C/MLnpiy5EKsfKWg=.",
      "google-site-verification=ALoYvB9LP05aK7ddKNWCSrNKI4QPPh647yXxmNq1rJ4",
      "globalsign-domain-verification=A899C94328AC5076D4198E6055E9C6E1",
      "atlassian-domain-verification=fMjaVWKHpJhM3aAlDYkNe5/yuAOUIOva2QexA9BN3WIHOkZmfqX9AWdaOicLtJYr",
      "MS=ms18093078",
      "google-site-verification=9SlseBmCRNaS8PoCIcXUBYR18HWP6RBX9HyD3R5R5Ls",
      "MS=91FCD146A8340927C3F9723C8F3DC44A5AE57414",
      "TAILSCALE-WN5I3ZooiwxJsVakFdjs",
      "logmein-verification-code=491874e6-5c3b-4b37-b19e-f523d7d74473",
      "ps-cd-verification=3e13eeb0-a25b-41af-a9d1-d5c8cca8082a",
      "tgXS6TJ3fVTnME8cpaIfgd9fe2rkAsn8kgSVRi/Af/c=",
      "globalsign-domain-verification=1FF9A93F847B1EB612F7EB378BFA8F2F",
      "cursor-domain-verification-fad4vy=0NZxtFJAF9pFISdFqx3nMzNyk",
      "google-site-verification=GEYwmfZ7RuvBcI7BT6xQnrNfn1z7gWUKLfVIalnwqeA",
      "globalsign-domain-verification=6FFE99D6D65D30A44C49A374C5143D87",
      "globalsign-domain-verification=607B2BE93D2B60F139751C389A14C13B",
      "v=spf1 ip4:208.75.120.0/22 ip4:205.207.104.0/22 include:_ext.constantcontact.com include:_spf.salesforce.com include:_spf.google.com ~all",
      "google-site-verification=Gp7Hv6yLosjKQ_t7gHJROnXoAYK7wlz1XLOBHt_J7HE",
      "jamf-site-verification=aFdwoWd1sPeHAeoixINgyw",
      "pendo-domain-verification=n9rM3WLge63EWPA3kOPW1OUEcXg",
      "google-site-verification=5lHEZKPh-_wYKf6iPhatHRpXj2l0R9NmPQ9wSWIAQag",
      "Cb20W914dVUL9V8ziCkX1Qo",
      "globalsign-domain-verification=1FF969BDF7F6D9B06243EFA8042CBDE7"
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
    "globalsign-domain-verification=83DF7D9B4CADBA9AB6D6ED1792F009A4",
    "reachdesk-verification=1CmlRrcJcF7N7kW8ionhhGt21vydYDeiaGjRKoFAJHCsTyxLVFHOcdUBx",
    "canva-site-verification=ZyZ5z6fQIoIHCDU_U8K6YQ",
    "anthropic-domain-verification-y2453z=RP4EoX2XlEAObiHw4Qyfxyif2",
    "stripe-verification=685340051470B5606798FED265AD82838FDC4D525047AEBAC6F8577B731D"
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
      "aia_ocsp": "http://ocsp.globalsign.com/ca/gsatlasr3ovtlsca2025q4",
      "serial": 2234390834872037099429134943735646257,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.globalsign.com/ca/gsatlasr3ovtlsca2025q4.crl"
      ],
      "subject_dn": "310b30090603550406130255533116301406035504080c0d4d6173736163687573657474733110300e06035504070c0757616c7468616d311f301d060355040a0c16436f6e7374616e7420436f6e746163742c20496e632e311e301c06035504030c152a2e636f6e7374616e74636f6e746163742e636f6d",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312e302c06035504031325476c6f62616c5369676e2041746c6173205233204f5620544c532043412032303235205134",
      "not_before": "20251110165448",
      "not_after": "20261212165447"
    },
    "ocsp": "http-400"
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
  "x12": {
    "status": 301,
    "ptr": [
      "www.constantcontact.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.constantcontact.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "not-offered",
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
      "url": "http://crl.globalsign.com/ca/gsatlasr3ovtlsca2025q4.crl",
      "status": 200
    }
  },
  "elapsed_s": 40.7,
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
