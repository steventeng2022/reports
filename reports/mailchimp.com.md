# Security Audit Report — mailchimp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mailchimp.com/ |
| Bug bounty program | Intuit |
| Listed scope domain | mailchimp.com |
| Test date | 2026-09-26 23:32 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 5, Info: 13)

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
| 18 | info | ERR1 | Error-page technology fingerprint | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
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
- **Detail:** Header reveals: AkamaiGHost
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=iBzo6FrDJ3rlsGoEUXL_YNHKVreLxzetIZRuCUlnBeQ; google-site-verification=WW0kxheERt2YHAEclRL_5DCFawde0CCdmJtXyNXS_7I; google-site-verification=FCp4CIH0-oOMadlYtNFvxRTI9_2zW1WDkXFR7pV8kPg
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.digicert.com -> http-200
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.209.216.105 carries PTR a23-209-216-105.deploy.static.akamaitechnologies.com. for mailchimp.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkk4gszxjfxiar.html -> 403; error page/headers match: Akamai.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

## Evidence (raw response observations)

```json
{
  "domain": "mailchimp.com",
  "dns": {
    "a": [
      "23.209.216.105"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx2.intuit.iphmx.com (pref 5)",
      "mx1.intuit.iphmx.com (pref 5)"
    ],
    "ns": [
      "a6-66.akam.net.",
      "a1-205.akam.net.",
      "a5-65.akam.net.",
      "a4-65.akam.net.",
      "a14-66.akam.net.",
      "a7-66.akam.net."
    ],
    "caa": [
      "0 issue \"pki.goog\"",
      "0 issue \"amazonaws.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"digicert.com\""
    ],
    "spf": [
      "o0m1nz3r7t",
      "google-site-verification=iBzo6FrDJ3rlsGoEUXL_YNHKVreLxzetIZRuCUlnBeQ",
      "smartsheet-site-validation=iJlsJdcpCMM9BUovg1yWWyqVYfZZWDdx",
      "google-site-verification=WW0kxheERt2YHAEclRL_5DCFawde0CCdmJtXyNXS_7I",
      "google-site-verification=FCp4CIH0-oOMadlYtNFvxRTI9_2zW1WDkXFR7pV8kPg",
      "google-gws-recovery-domain-verification=48989807",
      "zscaler-verification-42108621-10312025-7GNw9T",
      "onetrust-domain-verification=c77e00667a61495a933ef5219a1f71db",
      "onetrust-domain-verification=39a9942af0b642f1b6d2129f2aeaa1cc",
      "MS=5D41393E1B1E2A326C6154F96B8D4EEBDC58A667",
      "atlassian-domain-verification=rOuxrbpoM8X0dyjve2lLYnnHEXBtmxbGzk17YgboFB62K3dXo2gnekijahD5DdOg",
      "zapier-domain-verification-challenge=7f0c4720-f8f2-4f40-b264-cb21fe731403",
      "digicert-domain-verification-api=_l7n57xjtvdexvstchmg2p9g0647df5j",
      "google-site-verification=6dAIWpnctxIKj5r1bLhn2iGED8AGy8W_17S6scTDbbw",
      "MS=ms64719398",
      "_hzhrvm90xu668iuj6wb6s6swrxpa130",
      "v=spf1 ip4:205.201.128.0/20 ip4:198.2.128.0/18 ip4:148.105.0.0/16 ip4:129.145.74.12 include:_spf.google.com include:mailsenders.netsuite.com include:_spf2.intuit.com ",
      "include:_spf.qualtrics.com ip4:199.33.145.1 ip4:199.33.145.32 ip4:35.176.132.251 ip4:52.60.115.116 ~all",
      "digicert-domain-verification=_6g0u9nlv0mrvwb42upf06tgvu9gfum0",
      "apple-domain-verification=rtX1pAADNqH2UyA1vjbkylBSL92ZkTBvvFt54v3z5ck",
      "google-site-verification=HceFICpk7mLeoOmNAIxQyKx6NMEEjRlNgU_GC7UmaZI",
      "_5ztv7l82u6qsfemlfu89jyhrhyho2z1",
      "google-site-verification=qSv3r3tfEN8dtGaL1jVStrokm_jKImsl4cvgUG_6q5g",
      "_72ru7fr8c0ncfmjg71hyedfisw40m4h",
      "digicert-verification=zp2grw3qhjdfrzqpyybxtfbpzrk266g7",
      "google-site-verification=gYGKtLPycLOsWo5xUlOOGWsvENDmTYIt1X9iE1PZEP8",
      "_4u0mlvjxxxpqyv676anx8wkajzdzk0q",
      "adobe-idp-site-verification=b462bb17fbdf88e847859454079da73265c27a30a38d2c83f4a6e21a085a6d72",
      "google-site-verification=kjsRysndjNMMbqiWeLDEWuFKQifOKoBTpHJWZhFwr6E",
      "facebook-domain-verification=hmwpoaxoffl9lyv7a1jag656uo66wb",
      "onetrust-domain-verification=a014c8e6937e453f8448babef5311dfd",
      "mandrill_verify.5xzlEj2UVG87cZHpVJCi1A",
      "apple-domain-verification=VyVmVW02Ds1n6FQa",
      "docusign=a0dc4d7a-5002-4653-bb4f-959c68aa9074",
      "google-site-verification=ruul5w2E3u_oxPm-3xBtwAPFtTus0sysqVmIxy5frlg"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:19ezfriw@ag.dmarcian.com,mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:19ezfriw@fr.dmarcian.com,mailto:dmarc_ruf@emaildefense.proofpoint.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Diego, organizationName=Intuit Inc., commonName=mailchimp.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jan  9 00:00:00 2026 GMT",
    "notAfter": "Jan 16 23:59:59 2027 GMT",
    "san": [
      "mailchimp.com"
    ],
    "days_left": 112,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.209.216.105",
    "open": []
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.mailchimp.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 403
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 403,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 403,
    "/security.txt": 403,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=iBzo6FrDJ3rlsGoEUXL_YNHKVreLxzetIZRuCUlnBeQ",
    "google-site-verification=WW0kxheERt2YHAEclRL_5DCFawde0CCdmJtXyNXS_7I",
    "google-site-verification=FCp4CIH0-oOMadlYtNFvxRTI9_2zW1WDkXFR7pV8kPg",
    "google-gws-recovery-domain-verification=48989807",
    "zscaler-verification-42108621-10312025-7GNw9T"
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
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 14863057970580424955029290361646321922,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130953616e20446965676f31143012060355040a130b496e7475697420496e632e311630140603550403130d6d61696c6368696d702e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260109000000",
      "not_after": "20270116235959"
    },
    "ocsp": "http-200"
  },
  "x12": {
    "status": 403,
    "ptr": [
      "a23-209-216-105.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 403,
    "http_status": 403,
    "p404_status": 403,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 403,
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "elapsed_s": 7.8,
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
