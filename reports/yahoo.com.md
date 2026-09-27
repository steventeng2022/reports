# Security Audit Report — yahoo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yahoo.com/ |
| Bug bounty program | Yahoo! |
| Listed scope domain | yahoo.com |
| Test date | 2026-09-27 00:35 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 9 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 15 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 16 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 17 | info | SEC1 | security.txt published with a contact address | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 24 days (notAfter Oct 21 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ATS
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ATS
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 9. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.yahoo.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=w4N2bNopAWw1xYrdXKORILxx-WW3_LIiyX6dIMIidgk; google-site-verification=2b0Glh8l2icXIAgAcjOcFx16Jt26yWDgEyrk5hPD-ZY; facebook-domain-verification=gysqrcd69g0ej34f4jfn0huivkym1p
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.digicert.com -> http-200
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but yahoo.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 23 disallow path(s), e.g. /info/p.gif, /p/, /r/, /bin/, /caas/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 98.137.11.164 carries PTR media-router-fp73.prod.media.vip.gq1.yahoo.com. for yahoo.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 15. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The yahoo.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 16. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on yahoo.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of yahoo.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 17. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on yahoo.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

## Evidence (raw response observations)

```json
{
  "domain": "yahoo.com",
  "dns": {
    "a": [
      "98.137.11.164",
      "74.6.231.21",
      "74.6.143.25",
      "98.137.11.163",
      "74.6.143.26",
      "74.6.231.20"
    ],
    "aaaa": [
      "2001:4998:124:1507::f001",
      "2001:4998:24:120d::1:1",
      "2001:4998:124:1507::f000",
      "2001:4998:24:120d::1:0",
      "2001:4998:44:3507::8001",
      "2001:4998:44:3507::8000"
    ],
    "cname": null,
    "mx": [
      "mta5.am0.yahoodns.net (pref 1)",
      "mta7.am0.yahoodns.net (pref 1)",
      "mta6.am0.yahoodns.net (pref 1)"
    ],
    "ns": [
      "ns1.yahoo.com.",
      "ns3.yahoo.com.",
      "ns2.yahoo.com.",
      "ns4.yahoo.com.",
      "ns5.yahoo.com."
    ],
    "caa": [
      "0 issue \"digicert.com\"",
      "0 iodef \"mailto:security@yahooinc.com\"",
      "0 issue \"globalsign.com\"",
      "0 issue \"sectigo.com\""
    ],
    "spf": [
      "Zoom=13284637",
      "v=spf1 redirect=_spf.mail.yahoo.com",
      "edb3bff2c0d64622a9b2250438277a59",
      "google-site-verification=w4N2bNopAWw1xYrdXKORILxx-WW3_LIiyX6dIMIidgk",
      "google-site-verification=2b0Glh8l2icXIAgAcjOcFx16Jt26yWDgEyrk5hPD-ZY",
      "facebook-domain-verification=gysqrcd69g0ej34f4jfn0huivkym1p",
      "_globalsign-domain-verification=3rQPnwMFlx5UmUzSMV-JeDoNEMeG8BYFKvKDsHEzr9",
      "google-site-verification=Z3-Vh6zqUMgybVH4wQl1GxKSKN7JE13kyCyeZ3TZZ-I",
      "google-site-verification=GU8WAl0zPqaxdcZqDjuN7pqdfPCpR9Amz9rwxMG91qw",
      "google-site-verification=GLp01gkFNopm_JItbLxml4iuVbTgJa3rKu0-eq1RvsE",
      "google-site-verification=xoBvU6aKxP0gYgNL0iXqF0EccAg6nFrO7XxsHnc3iNQ",
      "google-site-verification=2b8irRvU5a2h4Mb-H_fdqNrqWjS00qmPfPcWqm8BhxI"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=Yahoo Holdings Inc., commonName=yahoo.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jul 28 00:00:00 2026 GMT",
    "notAfter": "Oct 21 23:59:59 2026 GMT",
    "san": [
      "yahoo.com",
      "tw.rd.yahoo.com",
      "s.yimg.com",
      "mbp.yimg.com",
      "hk.rd.yahoo.com",
      "fr-ca.rogers.yahoo.com",
      "ddl.fp.yahoo.com",
      "ca.rogers.yahoo.com",
      "ca.my.yahoo.com",
      "brb.yahoo.net",
      "add.my.yahoo.com",
      "*.yahoo.com",
      "*.www.yahoo.com",
      "*.media.yahoo.com",
      "*.att.yahoo.com",
      "*.amp.yimg.com"
    ],
    "days_left": 24,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "98.137.11.164",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: ATS"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.yahoo.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://yahoo.com/"
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
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=w4N2bNopAWw1xYrdXKORILxx-WW3_LIiyX6dIMIidgk",
    "google-site-verification=2b0Glh8l2icXIAgAcjOcFx16Jt26yWDgEyrk5hPD-ZY",
    "facebook-domain-verification=gysqrcd69g0ej34f4jfn0huivkym1p",
    "_globalsign-domain-verification=3rQPnwMFlx5UmUzSMV-JeDoNEMeG8BYFKvKDsHEzr9",
    "google-site-verification=Z3-Vh6zqUMgybVH4wQl1GxKSKN7JE13kyCyeZ3TZZ-I"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 4403766392697839781697990195366834791,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "subject_dn": "310b30090603550406130255533111300f060355040813084e657720596f726b3111300f060355040713084e657720596f726b311c301a060355040a13135961686f6f20486f6c64696e677320496e632e31123010060355040313097961686f6f2e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260728000000",
      "not_after": "20261021235959"
    },
    "ocsp": "http-200"
  },
  "http2": {
    "robots_disallow": [
      "/info/p.gif",
      "/p/",
      "/r/",
      "/bin/",
      "/caas/",
      "/blank.html",
      "/includes/",
      "/_td_api",
      "/tdv2_fp",
      "/nel_ms",
      "/fp_ms",
      "/sports_fp_ms",
      "/search_ms",
      "/_tdpp_api",
      "/_remote"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "media-router-fp73.prod.media.vip.gq1.yahoo.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.yahoo.com/",
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
    "security_txt": "/.well-known/security.txt",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "elapsed_s": 43.4,
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
