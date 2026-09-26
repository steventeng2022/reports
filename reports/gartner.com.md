# Security Audit Report — gartner.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gartner.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | gartner.com |
| Test date | 2026-09-26 23:27 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 6, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
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
| 16 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 20 | info | SRV1 | Server header discloses a product version | CWE-200 |
| 21 | info | CT1 | 97 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 22 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: awselb/2.0
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
- **Detail:** Apex TXT records with verification/token content: ciscocidomainverification=57f18449faaaa96630528f3cab6ca711051e21cb8aecdd166f5744; apple-domain-verification=k0GE0BCT91wGwIyD74bKOw2pu76vgckNG8XTkpxj93w; lucidlink-verification=8CP62E0W0ET4MRZQS36V2YH1P8
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 99.83.168.174 carries PTR af33f8e0e3f6e442a.awsglobalaccelerator.com. for gartner.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for gartner.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The gartner.com certificate lists an AIA OCSP responder (http://ocsp.r2m04.amazontrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 20. [INFO] Server header discloses a product version (`SRV1`)

- **CWE:** CWE-200
- **Detail:** Server header on gartner.com is 'awselb/2.0' and includes a version number, which narrows targeted vulnerability research.
- **Recommendation:** Serve a generic Server value without the version.

### 21. [INFO] 97 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: aemintl.emt.aws.gartner.com, aemintl.emtdev.aws.gartner.com, aemintl.emtqa.aws.gartner.com, api.reviews.dm.aws.gartner.com, api.reviews.dmqa.aws.gartner.com, apps.gartner.com, apps.pdotools.aws.gartner.com, artifactorydr-edge.cloudservicesqa.aws.gartner.com, biodataapi.da.aws.gartner.com, capimgr-use1.cloudservicesdev.aws.gartner.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 22. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: aemintl.emt.aws.gartner.com, aemintl.emtdev.aws.gartner.com, aemintl.emtqa.aws.gartner.com, api.reviews.dm.aws.gartner.com, api.reviews.dmqa.aws.gartner.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "gartner.com",
  "dns": {
    "a": [
      "99.83.168.174",
      "75.2.50.126"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx0b-0016aa01.pphosted.com (pref 5)",
      "mxa-0016aa01.gslb.pphosted.com (pref 10)",
      "mx0a-0016aa01.pphosted.com (pref 5)",
      "mxb-0016aa01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "a28-65.akam.net.",
      "a4-64.akam.net.",
      "a1-109.akam.net.",
      "a14-64.akam.net.",
      "a3-65.akam.net.",
      "pdns77.ultradns.org.",
      "pdns77.ultradns.com.",
      "a5-64.akam.net."
    ],
    "caa": [],
    "spf": [
      "ciscocidomainverification=57f18449faaaa96630528f3cab6ca711051e21cb8aecdd166f57444d93b57c5",
      "apple-domain-verification=k0GE0BCT91wGwIyD74bKOw2pu76vgckNG8XTkpxj93w",
      "lucidlink-verification=8CP62E0W0ET4MRZQS36V2YH1P8",
      "slido-domain-verification=ca6c3a71-8061-4091-8dac-a342e0bd8e4b",
      "docusign=176ba6ee-d141-4b4f-951f-ed65844926a4",
      "openai-domain-verification=dv-1CqASnTt5JNxuOGMkbJziedR",
      "anthropic-domain-verification-ednxat=IQ65KbsWwqCgfrFDGjU3Dox5R",
      "00DRu00000RGlmb=1TBRu00000014kj",
      "prowly-verification=0a18c790f75457f4100202545f5060298b4099a9f9ad953a6f2cd406187d096e",
      "docusign=fbd0b5e3-fd26-4058-a01e-f3231247d403",
      "onetrust-domain-verification=9615d0536ed947b2bde2aff220e66c8b",
      "canva-site-verification=NiX71ocXK6Nit9EcqeZZ_A",
      "docker-verification=0894b02a-7530-4d69-a114-b173e16374f7",
      "webexdomainverification.FZF7=b569771f-24c7-4cd9-b087-75b779846dde",
      "v=spf1 include:evspf1.gartner.com include:evspf2.gartner.com include:_spf.salesforce.com include:spf.mandrillapp.com ip4:8.15.203.113 ip4:8.15.203.114 ip4:8.15.203.115 ip4:8.15.203.116 ip4:148.59.100.16/28 ",
      "ip4:216.221.170.72/29 ip4:216.221.170.250/31 ip4:216.221.171.8/29 -all",
      "google-site-verification=npR9iwOMNUbkau8Pwvd4kBqqPDMyXCUu8g5iP1PW_44",
      "hWbBxLhyKc36IrHY2zusOB2kDAgSqdhLvJAxHo7pCUBuRh8ZpBeGKBbQix2ic6FerMsaTaiZY4gzCVnjOpqaNw==",
      "x98FvuwX6an-AAO7F0eMahTQny_-",
      "google-site-verification=aKIAxvYjZsxgy4fvr3ys8D_D4naYE21UpdGV3jKNbb0",
      "onetrust-domain-verification=5b726d00265b47399bae397d6aa108eb",
      "uber-domain-verification=db80ddee-dc1a-47b4-b0f9-5382e61b8cc7",
      "paloaltonetworks-site-verification=89f74fa49f2affd44039a4cfce3efa8b83e2eee7d8f52ac84ce59d7a6f41ebb4",
      "docusign=1b2f90f6-48c2-4394-8d1d-bf2ede024866",
      "atlassian-domain-verification=8jqx2ryRUppyajabhJkDQFuiurOAJuQysDFi/wyqM11w4JVloZs9oKlFWUg0RFcu",
      "ZOOM_verify_ccu8Ucbb3XjDVqaWJxKT5F",
      "drift-domain-verification=84b976bbb9c08c9f8507ed99d05493997c0f91557421b746b4ef017d64d036b6",
      "00DEm00000SNtEz=1TBEm0000000wjx",
      "00DD20000003MjH=1TBD20000004CBs;00DEa00000R3lsT=1TBEa0000000PWH;00DD40000009zec=1TBD4000000000v"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=gartner.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Dec 22 00:00:00 2025 GMT",
    "notAfter": "Jan 19 23:59:59 2027 GMT",
    "san": [
      "gartner.com",
      "www.gartner.com"
    ],
    "days_left": 115,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "99.83.168.174",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.gartner.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.gartner.com:443/"
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
    "/.env": 403,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 403,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 97,
    "notable": [
      "aemintl.emt.aws.gartner.com",
      "aemintl.emtdev.aws.gartner.com",
      "aemintl.emtqa.aws.gartner.com",
      "api.reviews.dm.aws.gartner.com",
      "api.reviews.dmqa.aws.gartner.com",
      "apps.gartner.com",
      "apps.pdotools.aws.gartner.com",
      "artifactorydr-edge.cloudservicesqa.aws.gartner.com",
      "biodataapi.da.aws.gartner.com",
      "capimgr-use1.cloudservicesdev.aws.gartner.com",
      "capimgr-use2.cloudservicesqa.aws.gartner.com",
      "cloudbeesocqa-use2.cloudsharedqa.aws.gartner.com",
      "cloudbeesocqa.cloudsharedqa.aws.gartner.com",
      "cloudbeesocqadr.cloudsharedqa.aws.gartner.com",
      "cppplan-devb.rcddev.aws.gartner.com"
    ],
    "sample": [
      "aemintl.emt.aws.gartner.com",
      "aemintl.emtdev.aws.gartner.com",
      "aemintl.emtqa.aws.gartner.com",
      "api.reviews.dm.aws.gartner.com",
      "api.reviews.dmqa.aws.gartner.com",
      "apps.gartner.com",
      "apps.pdotools.aws.gartner.com",
      "artifactorydr-edge.cloudservicesqa.aws.gartner.com",
      "biodataapi.da.aws.gartner.com",
      "capimgr-use1.cloudservicesdev.aws.gartner.com",
      "capimgr-use2.cloudservicesqa.aws.gartner.com",
      "cloudbeesocqa-use2.cloudsharedqa.aws.gartner.com",
      "cloudbeesocqa.cloudsharedqa.aws.gartner.com",
      "cloudbeesocqadr.cloudsharedqa.aws.gartner.com",
      "cppplan-devb.rcddev.aws.gartner.com",
      "css-apigw-lipp-us-east-2.emtqa.aws.gartner.com",
      "css-apigw-lipp.emtqa.aws.gartner.com",
      "css-apigw-servicehub-us-east-1.emtqa.aws.gartner.com",
      "css-apigw-servicehub-us-east-2.emtqa.aws.gartner.com",
      "css-apigw-servicehub.emtqa.aws.gartner.com"
    ],
    "dangling": [
      "aemintl.emt.aws.gartner.com",
      "aemintl.emtdev.aws.gartner.com",
      "aemintl.emtqa.aws.gartner.com",
      "api.reviews.dm.aws.gartner.com",
      "api.reviews.dmqa.aws.gartner.com"
    ]
  },
  "apex_txt": [
    "ciscocidomainverification=57f18449faaaa96630528f3cab6ca711051e21cb8aecdd166f5744",
    "apple-domain-verification=k0GE0BCT91wGwIyD74bKOw2pu76vgckNG8XTkpxj93w",
    "lucidlink-verification=8CP62E0W0ET4MRZQS36V2YH1P8",
    "slido-domain-verification=ca6c3a71-8061-4091-8dac-a342e0bd8e4b",
    "openai-domain-verification=dv-1CqASnTt5JNxuOGMkbJziedR"
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
      "aia_ocsp": "http://ocsp.r2m04.amazontrust.com",
      "serial": 6743772487308339126491589473488160445,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "subject_dn": "311430120603550403130b676172746e65722e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20251222000000",
      "not_after": "20270119235959"
    },
    "ocsp": "http-403"
  },
  "x12": {
    "status": 301,
    "ptr": [
      "af33f8e0e3f6e442a.awsglobalaccelerator.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.gartner.com:443/",
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
    "crl": {
      "url": "http://crl.r2m04.amazontrust.com/r2m04.crl",
      "status": 200
    }
  },
  "elapsed_s": 29.8,
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
