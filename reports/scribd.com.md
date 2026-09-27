# Security Audit Report — scribd.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://scribd.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | scribd.com |
| Test date | 2026-09-27 00:31 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 3, Info: 13)

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
| 15 | info | SEC2 | security.txt published without a contact address | CWE-1038 |
| 16 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
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
- **Detail:** Header reveals: Varnish
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=Ouatu7eN_H_KCzvQGZ-_XLCABWvFM1Ofb4b4hd6ERlg; stripe-verification=33707726fea82073ff209aaaeea9f178ca9acdffeb4077b12e4903f92fb9; globalsign-domain-verification=Bo6R5k9s2Zwdk5OoeybGk6L2EHx_oV1TqLgGiMR4IQ
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of scribd.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] security.txt published without a contact address (`SEC2`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt returns 200 but contains no mailto:/URL contact.
- **Recommendation:** Add a Contact: field per RFC 9116.

### 16. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on scribd.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

## Evidence (raw response observations)

```json
{
  "domain": "scribd.com",
  "dns": {
    "a": [
      "151.101.2.152",
      "151.101.66.152",
      "151.101.194.152",
      "151.101.130.152"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-00957a01.gslb.pphosted.com (pref 10)",
      "mxb-00957a01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-2000.awsdns-58.co.uk.",
      "ns-474.awsdns-59.com.",
      "ns-1449.awsdns-53.org.",
      "ns-630.awsdns-14.net."
    ],
    "caa": [
      "0 issuewild \"letsencrypt.org\"",
      "0 issuewild \"amazon.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"amazon.com\""
    ],
    "spf": [
      "ZOOM_verify_qVwNF9TlQp6oTxlx4v4GaA",
      "google-site-verification=Ouatu7eN_H_KCzvQGZ-_XLCABWvFM1Ofb4b4hd6ERlg",
      "stripe-verification=33707726fea82073ff209aaaeea9f178ca9acdffeb4077b12e4903f92fb9a984",
      "globalsign-domain-verification=Bo6R5k9s2Zwdk5OoeybGk6L2EHx_oV1TqLgGiMR4IQ",
      "d726596f-b232-406c-8660-a7b13b279ffa",
      "an2A85lK4eCI+OVQMZRFZ92bkimP99x1WRAzoj7qp/4=",
      "apple-domain-verification=eURIxHjDOv6GMt8T",
      "google-site-verification=Bys0QJsmUcCJ_qCpq6KaSZc2gravmyYLN_EUFENpitg",
      "spacelift-domain-verification=sjdhfkj3dew",
      "stripe-verification=27d898303b37a8f26350e9d801f6ad3fa671bfd01b2b4f8951e6f1c90ead34e3",
      "google-site-verification=GggGFvM_T09I1X94IiW555WcOjp5NmcZm-GVh406J44",
      "v=spf1 include:_s00992988.autospf.email include:mailgun.org ~all",
      "mgverify=0ab08701ae09a23d0bc2c38fae847d8f307797fcb1697237391f8128a9640651",
      "mixpanel-domain-verify=aedfc989-2797-4ab3-99e3-ba642eda5fe9",
      "docusign=fd9b486a-4340-4798-abab-26ce168b0f1b",
      "MS=ms82626852",
      "cursor-domain-verification-50y66e=D8Uwu2yc3eEBkRMlwCQjSf2gN",
      "v=spf2.0/mfrom v=spf1 include:_s00992988.autospf.email include:mailgun.org ~all",
      "openai-domain-verification=dv-JENRwA8a0uUEogtGOcdZfVk8",
      "stripe-verification=07e715389ac4f3434a3223a1e6cd2b7680d193d73de136cde05634188cfdf939",
      "openai-domain-verification=dv-eOTOMtNqRWMP9Hwl6UWrtzxb",
      "atlassian-domain-verification=suO/cHhqQzi2PxMPyb8WEZvFWrAq3fuOv1RfohRyRATHt6P05jFpTBAt9kXV8bVw",
      "facebook-domain-verification=svgb7p4y0mkb2o8bjoufff7qvp8f10",
      "anthropic-domain-verification-npy3tx=XrE3YAnz8zeSAImkTUoc1n9eY",
      "segment-site-verification=EJ46G3zd9xfa1md1S3RxDcsZ9olNj7hf",
      "github-verification=yRBhv3c3EK2QxM9aeLKy8TT2E4NuSZPuGRSCROOP"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@dmarc.250ok.net; ruf=mailto:dmarc_fr@dmarc.250ok.net; fo=1; pct=100; rf=afrf"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.scribd.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug 26 16:53:08 2026 GMT",
    "notAfter": "Nov 24 16:53:07 2026 GMT",
    "san": [
      "*.scribd.com",
      "scribd.com"
    ],
    "days_left": 58,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.2.152",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [
    {
      "domain": ".scribd.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.scribd.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://scribd.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 308
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=Ouatu7eN_H_KCzvQGZ-_XLCABWvFM1Ofb4b4hd6ERlg",
    "stripe-verification=33707726fea82073ff209aaaeea9f178ca9acdffeb4077b12e4903f92fb9",
    "globalsign-domain-verification=Bo6R5k9s2Zwdk5OoeybGk6L2EHx_oV1TqLgGiMR4IQ",
    "apple-domain-verification=eURIxHjDOv6GMt8T",
    "google-site-verification=Bys0QJsmUcCJ_qCpq6KaSZc2gravmyYLN_EUFENpitg"
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
      "serial": 562330394700488342624366787678353596126044,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://yr1.c.lencr.org/93.crl"
      ],
      "subject_dn": "3115301306035504030c0c2a2e7363726962642e636f6d",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303595231",
      "not_before": "20260826165308",
      "not_after": "20261124165307"
    }
  },
  "http2": {
    "hsts_preloaded": true
  },
  "x12": {
    "status": 302
  },
  "x13": {
    "root_status": 302,
    "root_location": "https://www.scribd.com/",
    "http_status": 301,
    "p404_status": 302,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 302,
    "hsts": "max-age=63072000; includeSubDomains; preload",
    "crl": {
      "url": "http://yr1.c.lencr.org/93.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 302
  },
  "elapsed_s": 18.3,
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
