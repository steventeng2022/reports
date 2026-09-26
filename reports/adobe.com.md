# Security Audit Report — adobe.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://adobe.com/ |
| Bug bounty program | Adobe |
| Listed scope domain | adobe.com |
| Test date | 2026-09-26 18:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=86400 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: astro-domain-verification=cmo1ytx0m311601op0whjgp35; wiz-domain-verification=a9f3fccbe5b3431e0f1ba884d9b79957c90236ede5364371b3dc9ac3; postman-domain-verification=dec911a3f40f55ba9067f40b09e03a31bbadde3fe54be7d873dc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of adobe.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but adobe.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 203.121.225.70 carries PTR n225-h70.121.203.dynamic.da.net.tw. for adobe.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "adobe.com",
  "dns": {
    "a": [
      "203.121.225.70",
      "203.121.225.79"
    ],
    "aaaa": [
      "2600:1417:e800::b81a:7f9b",
      "2600:1417:e800::b81a:7fa0"
    ],
    "cname": null,
    "mx": [
      "adobe-com.mail.protection.outlook.com (pref 1)",
      "adobe.mail.protection.outlook.com (pref 2)"
    ],
    "ns": [
      "a1-217.akam.net.",
      "a10-64.akam.net.",
      "a13-65.akam.net.",
      "a28-67.akam.net.",
      "a26-66.akam.net.",
      "a7-64.akam.net."
    ],
    "spf": [
      "_y59yjxuzvzwtqes5yotts3o7drxpebh",
      "astro-domain-verification=cmo1ytx0m311601op0whjgp35",
      "wiz-domain-verification=a9f3fccbe5b3431e0f1ba884d9b79957c90236ede5364371b3dc9ac3104ee588",
      "postman-domain-verification=dec911a3f40f55ba9067f40b09e03a31bbadde3fe54be7d873dc792017b17a95",
      "drift-domain-verification=ce77053dc2d9b73c71437d5afda3b6d06fbc34a1b0e4527fe81c55e0d99ca4b4",
      "stripe-verification=6fc5c32209614c905d88a1cff92d08be1eff034a63a75ebdf8da94e4cfb4c51a",
      "elevenlabs=7WqXlRwQh8-jH2984SP4TQCS0MWL3IoSp8kynyVKVg8",
      "98a8944ee0d54f6798380941906d6241",
      "atlassian-domain-verification=9uYxhBbyOGbk9B1aIn6fheLO/Cg08iHVd7RwDuaDQ8IVEhyfFeCc6gTAxw3kWShW",
      "infoblox-domain-mastery=3108de0dabfcb3ea00012e62f97a49e46d9f5ceee0e661cad991cfc66c01de8604",
      "google-site-verification=P_kb2Yyzww7fnZitZ6EbIYipWkjkin9et6IsSwDp7lg",
      "google-site-verification=B29h-nx4tgaIP-yB-xsD_JqsPObknGvdOxV0E-yhjhY",
      "wiz-domain-verification=26e5ac5462828fa23e5f31397b264c91aad3a981a3c7aaef7ede783310d6d88e",
      "DXpQZzX4rXJPkCKMkVXs/GYPXzPHerZdxcw5iIMxFy9AjmN9DJ0bat/TqD5cRS/CpsN2Rk9y7NH1FfQkGS3vWg==",
      "dd6i3kj0094qcnaaobqkhhvr",
      "token value: 34150eb3cd1c4415972199b62fd720d0",
      "openai-domain-verification=dv-xsmU3ZeWiAU4L5v23bd1l0tS",
      "google-site-verification=eXDd-kvIdj03OtZ6z7vWwIHZ79QbuQTMIpnwTcwGHR0",
      "google-site-verification=6WBkBMyLUyWUihnTjeP53f3TcSi90ejKJk-gmL2eqgE",
      "fastly-domain-delegation-mcmjcm11052020-05-11-2020",
      "google-site-verification=0RAkrqlyPGIM-rT1AOB-DNOw3eifD6i7G__e5BtnTz8",
      "openai-domain-verification=dv-IMsFRlt9z7lWnxvZwq5CT0PS",
      "adobe-sign-verification=bb81bc75163acd737f022c8b8ac3958a5f3600ba3daaaa5fad01d44924f21fad",
      "facebook-domain-verification=3rlk6hdq3nk34qcs4bsz8dua9a1hoa",
      "_globalsign-domain-verification=4JjiCeoO4ZI71Wz54ZByVZYNBLNCDNPcLz4lv0Qlzf",
      "google-site-verification=0qCZ1upUojha2X6XQplDtCuE9sdGSke4oVbOzBnwPnU",
      "anthropic-domain-verification-xjxses=aaN5uq8fdNr0u4oUdkOTRwdJl",
      "docker-verification=e639ae3e-ec26-47da-af6e-bf451aa076c0",
      "openai-domain-verification=dv-0x0B91zX2Jyh5Z5UYxGYSJry",
      "Fastly-Domain-Verify-as9dfas8d8fa7-sd707sdfasdf908",
      "atlassian-domain-verification=MuhJPcv3bzIQ9BHg1GjhQfmq+1evcqT7fB9gGJn4aOmE2HExlRuwjr5EE7/nABXh",
      "zapier-domain-verification-challenge=389e1047-a056-4e10-8f7b-e547e30d978d",
      "google-site-verification=V6qGlS2Yhp2Ua8FCIv2cYVgBEjXeQTl4UBNS07bKuSs",
      "_globalsign-domain-verification=lnj0iZGjUp0BOSg71asjUWlkcoKSaMz2EMksT9_CUS",
      "parallels-domain-verification=cbe7f671fa8c4726b984182169e51fed78687863a4e8476383b56e030a6c7037",
      "adobe-sign-verification=9c3b7ea5e23da29a4a3d23d89c194c4914a70966bd944c13d54e2f37ecfe327d",
      "ddj6i3kj0094qcnaaobqkhhvr",
      "google-site-verification=Q86EnJZ_pwCfS8VpA1rlQPS3HXZzrcCWGD68zb74InY",
      "google-site-verification=v-817iF9e0_UdjWiz3gtCfMvYr8CVFt1Ej4QvMq640U",
      "wiz-domain-verification=3203c8f5ea0165b12b9b9fc41976d5e8a1dbdbd57e1edaff5049be78970f60e1",
      "mandrill_verify.qFmG2YBGhKd446rthmMirQ",
      "google-site-verification=Rg8rw6QFcht0wbcstENHTQ3h5l_ujrfBPxhuE7cfBFE",
      "wiz-domain-verification=bdc81d690c2dc882dda52211cbc3035ef4d29dbe62b95c9333569faefe62269e",
      "fastly-domain-delegation-rQNX3KD7DKL9hmeR-378696-2021-06-09",
      "google-site-verification=zA4EW3kDxiYfsHq_yBFuRqahndRXC63MjptuXgmShiw",
      "work-accounts-domain-verification=sw2BDQA7hLlnLixW6cxkNzgK0EBTsC",
      "cisco-ci-domain-verification=6e22d6f101dd96dc12fabfe843ff4e6748b9f7a89af1ff342476b923f01e4292",
      "_github-challenge-adobe=94b215a3c7",
      "adobe-sign-verification=67f2a35c977e36cad988ec4e1f3abfe3c1bc34f10e5c0f0ff37dbc0fde25569e",
      "adobe-sign-verification=162a03947665f096b642e5f54ebfa413066e7b98d14381cda74d385637c5695e",
      "google-site-verification=gDyvme6Q3LVye5JqFODK2wmzdteJCvQ8M8F4hhclEuE",
      "neat-pulse-domain-verification-rXqzBGM=023e9dc4-e375-4205-8724-8d1a441e6d5b",
      "miro-verification=2a1b8fd92b346bd4b1d8e3d2e42517e031841d95",
      "google-site-verification=LHlbZB7X6SCdg21EUgwZbdJTd1jgpCNCTzVEVoOv2nU",
      "fastly-domain-delegation-610920-202365",
      "google-site-verification=FHduugscCIWrobl53QpXxe06TdV0FWOCWgV1i-NQIBc",
      "gitkraken-domain-verification=b48e62e0b5b3d92167c9c4a087364734970a7f8c3cf984b1a62acc8921ea22c3",
      "v=spf1 exists:%{i}._i.%{d}._d.espf.agari.com include:%{d}.55.spf-protect.agari.com include:_spf.intacct.com IP4:172.193.27.96 -all",
      "g7ck5d9xyrzg0yjrznjksw4njp60rgqw",
      "intacct-esk=4FED1A4780E0FB23E0539806A8C0D680",
      "google-site-verification=VfGWzOLDyrmGv8t-bb5sGqNb8fyIhHvgC7cfRSBeKSw",
      "google-site-verification=itYd9UI50Y6f_P_ioQ4hpkoKWFXJOQHqkrr1DWUwxwg",
      "google-site-verification=WlkKAHcmf9lr7GeIymdFUnFVnlZBe8EsaUc5t3UASuE",
      "openai-domain-verification=dv-pN3CfPVdeBAANroxeTFmd7WZ",
      "google-site-verification=OCQ4NvNmnZ5O-G_OmpA4igVzqwDoRS2qDECNKajvSXQ",
      "DirectFedAuthUrl=https://adobe.okta.com/app/adobe_pwcmytransferentraprod_1/exk2604poe4LngmG50h8/sso/saml",
      "drift-domain-verification=502160a86dc2f7411dec54f019b785a7010eb9f38a6152011c1be40b89f68e9b",
      "mongodb-site-verification=9wz19h5hq4rETvHeWjbWVnTmNHgwaufJ",
      "openai-domain-verification=dv-Cf9stelxxYuIRVx3Kd0z28ks",
      "google-site-verification=IWlts5bv60RGLZCKTgxClTsuNLB9cT_09-pevXId2o8",
      "google-site-verification=TnZul_ScOVTUzNZBRNXsOyCnW5vK8xw43kkF420Ht1w",
      "airtable-verification=09e6c77695de8069dee51e5408d768ad",
      "google-site-verification=Ha-Xd-kkVATWpGhHF1C_FFoewdSb_AyD8GFgcH4DMxA",
      "google-site-verification=MnYkALPA4CNieThUZzzp4Hh88H5szHXokxqirdGFFN0"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:adobe@rua.agari.com; ruf=mailto:adobe@ruf.agari.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Jose, organizationName=Adobe Inc, commonName=*.adobe.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Jan  5 00:00:00 2026 GMT",
    "notAfter": "Jan  4 23:59:59 2027 GMT",
    "san": [
      "*.adobe.com",
      "adobe.com"
    ],
    "days_left": 100,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "203.121.225.70",
    "open": []
  },
  "https": {
    "status": 301,
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
      "origin": "https://sub.adobe.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://adobe.com/"
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
    "astro-domain-verification=cmo1ytx0m311601op0whjgp35",
    "wiz-domain-verification=a9f3fccbe5b3431e0f1ba884d9b79957c90236ede5364371b3dc9ac3",
    "postman-domain-verification=dec911a3f40f55ba9067f40b09e03a31bbadde3fe54be7d873dc",
    "drift-domain-verification=ce77053dc2d9b73c71437d5afda3b6d06fbc34a1b0e4527fe81c55",
    "stripe-verification=6fc5c32209614c905d88a1cff92d08be1eff034a63a75ebdf8da94e4cfb4"
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
      "not_before": "20260105000000",
      "not_after": "20270104235959"
    }
  },
  "x12": {
    "status": 301,
    "ptr": [
      "n225-h70.121.203.dynamic.da.net.tw."
    ]
  },
  "elapsed_s": 33.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
