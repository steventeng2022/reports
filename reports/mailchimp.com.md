# Security Audit Report — mailchimp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mailchimp.com/ |
| Bug bounty program | Intuit |
| Listed scope domain | mailchimp.com |
| Test date | 2026-09-25 09:57 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

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
      "a14-66.akam.net.",
      "a7-66.akam.net.",
      "a4-65.akam.net.",
      "a1-205.akam.net.",
      "a5-65.akam.net."
    ],
    "spf": [
      "google-site-verification=kjsRysndjNMMbqiWeLDEWuFKQifOKoBTpHJWZhFwr6E",
      "digicert-domain-verification=_6g0u9nlv0mrvwb42upf06tgvu9gfum0",
      "google-gws-recovery-domain-verification=48989807",
      "v=spf1 ip4:205.201.128.0/20 ip4:198.2.128.0/18 ip4:148.105.0.0/16 ip4:129.145.74.12 include:_spf.google.com include:mailsenders.netsuite.com include:_spf2.intuit.com ",
      "include:_spf.qualtrics.com ip4:199.33.145.1 ip4:199.33.145.32 ip4:35.176.132.251 ip4:52.60.115.116 ~all",
      "MS=5D41393E1B1E2A326C6154F96B8D4EEBDC58A667",
      "o0m1nz3r7t",
      "google-site-verification=qSv3r3tfEN8dtGaL1jVStrokm_jKImsl4cvgUG_6q5g",
      "google-site-verification=6dAIWpnctxIKj5r1bLhn2iGED8AGy8W_17S6scTDbbw",
      "google-site-verification=ruul5w2E3u_oxPm-3xBtwAPFtTus0sysqVmIxy5frlg",
      "google-site-verification=gYGKtLPycLOsWo5xUlOOGWsvENDmTYIt1X9iE1PZEP8",
      "apple-domain-verification=rtX1pAADNqH2UyA1vjbkylBSL92ZkTBvvFt54v3z5ck",
      "_4u0mlvjxxxpqyv676anx8wkajzdzk0q",
      "facebook-domain-verification=hmwpoaxoffl9lyv7a1jag656uo66wb",
      "adobe-idp-site-verification=b462bb17fbdf88e847859454079da73265c27a30a38d2c83f4a6e21a085a6d72",
      "_hzhrvm90xu668iuj6wb6s6swrxpa130",
      "_5ztv7l82u6qsfemlfu89jyhrhyho2z1",
      "onetrust-domain-verification=c77e00667a61495a933ef5219a1f71db",
      "docusign=a0dc4d7a-5002-4653-bb4f-959c68aa9074",
      "mandrill_verify.5xzlEj2UVG87cZHpVJCi1A",
      "apple-domain-verification=VyVmVW02Ds1n6FQa",
      "zscaler-verification-42108621-10312025-7GNw9T",
      "_72ru7fr8c0ncfmjg71hyedfisw40m4h",
      "google-site-verification=WW0kxheERt2YHAEclRL_5DCFawde0CCdmJtXyNXS_7I",
      "digicert-verification=zp2grw3qhjdfrzqpyybxtfbpzrk266g7",
      "atlassian-domain-verification=rOuxrbpoM8X0dyjve2lLYnnHEXBtmxbGzk17YgboFB62K3dXo2gnekijahD5DdOg",
      "digicert-domain-verification-api=_l7n57xjtvdexvstchmg2p9g0647df5j",
      "google-site-verification=iBzo6FrDJ3rlsGoEUXL_YNHKVreLxzetIZRuCUlnBeQ",
      "google-site-verification=HceFICpk7mLeoOmNAIxQyKx6NMEEjRlNgU_GC7UmaZI",
      "zapier-domain-verification-challenge=7f0c4720-f8f2-4f40-b264-cb21fe731403",
      "MS=ms64719398",
      "google-site-verification=FCp4CIH0-oOMadlYtNFvxRTI9_2zW1WDkXFR7pV8kPg",
      "onetrust-domain-verification=39a9942af0b642f1b6d2129f2aeaa1cc",
      "onetrust-domain-verification=a014c8e6937e453f8448babef5311dfd",
      "smartsheet-site-validation=iJlsJdcpCMM9BUovg1yWWyqVYfZZWDdx"
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
    "days_left": 113,
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 37.5,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
