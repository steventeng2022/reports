# Security Audit Report — accenture.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://accenture.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | accenture.com |
| Test date | 2026-09-27 00:08 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 1, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 8 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 9 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 10 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 11 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 12 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 13 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 14 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 15 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://accenture.com/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

### 6. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 7. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 8. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 9. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: lucidlink-verification=21YDN93BQD7FWH7K0D3XDPK2ZW; notion-domain-verification=gnhjuSDWpptmSxIQQ47C0Dp8nXcUME25kMxltXMAmii; cisco-ci-domain-verification=757b62f6f592352dcec308d68d984e829ffc63970f7a5257940
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 10. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but accenture.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 11. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 29 disallow path(s), e.g. */Careers/Registration, */Careers/Form, */Careers/Profiles, */error/, */loginpage
- **Recommendation:** Review disallowed paths; robots is not access control.

### 12. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of accenture.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 13. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 170.248.56.19 carries PTR acnpic.accenture.com., acnpic-careers.accenture.com., careers.accenture.com., accenture.com. for accenture.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 14. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for accenture.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 15. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The accenture.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

## Evidence (raw response observations)

```json
{
  "domain": "accenture.com",
  "dns": {
    "a": [
      "170.248.56.19"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx0b-001dcc01.pphosted.com (pref 10)",
      "mx0a-001dcc01.pphosted.com (pref 10)"
    ],
    "ns": [
      "amrns1501.accenture.com.",
      "cfans1002.accenture.com.",
      "apans3501.accenture.com.",
      "emens3501.accenture.com.",
      "cfans1001.accenture.com."
    ],
    "caa": [],
    "spf": [
      "smartsheet-site-validation=6WKcBZVtX1tBTc2dEsYpkswqp-BOFGHx",
      "lucidlink-verification=21YDN93BQD7FWH7K0D3XDPK2ZW",
      "notion-domain-verification=gnhjuSDWpptmSxIQQ47C0Dp8nXcUME25kMxltXMAmii",
      "Hp48LTxGknu4omlcp1bP0HqFH2VBFOLA88QS7zwDTJQaM2moc6schoR8P30qVYcuO/RK+cUiCTnntk5pSUk+SA==",
      "cisco-ci-domain-verification=757b62f6f592352dcec308d68d984e829ffc63970f7a52579405448c1f39b4f2",
      "MS=ms19684732",
      "atlassian-domain-verification=7KcyvCxeJOqBY5fwEHdp8/Nmk9RR7Am4Ihf65044gsFaDhwDtT3fmmt3gdGbur3M",
      "amazonses:8GzbTEmni2PBRv6jLZwAq1rcYGkbVEmlNuHIcahJ1K0=",
      "smartsheet-site-validation=owIJ5MLqX9KoiMfKRnEcU_FVn3xQVPlA",
      "monday-com-verification=3bD2wbN66_PVrOmLpWA5FS75DF9RC47efxRHg1SkrbQ",
      "stripe-verification=BB11E45F6EB04F0F3639CBC7E7C56E9579F457BCC44999D1BC492F3C8E03BE4E",
      "adobe-sign-verification=da99fb7e471e8e812595bd6a8c5e2875",
      "nulab-verification-code=8TTNkc4cj170WuQDQXnntAFmVZulfy8muhpysoP7FuaDXfoObfZUYi5GfIFFO5OI",
      "Dynatrace-site-verification=cf509ddc-d5d6-43a1-a4c2-c120d3b0933b__v9qm0u1chpsc5jhkdpafn869s3",
      "nulab-verification-code=k4l5aMXngpLUhKTLEuiHj2dDFSUBLxoKetjixslAkfHvvwcBagg14LmP9Ru4xUZO",
      "clayton-domain-verification=b74f705c0b4e4369823f5e0717bdaba2abeb4b48d5",
      "mgverify=c915af45fa137c480f06991086887c26f5e025e8a973c8cbaaefddaf7e5119d0",
      "asv=c7a401fd2ce4afdc4c9898caee92a999",
      "docusign=614ac0a7-7549-4436-b0f7-d6465424f092",
      "sinch-domain-verification=ad65d33d-c9d1-491c-9349-86fa8b0bfc4a",
      "00D4P000000i2Tx=1TBaZ00000003SX",
      "cursor-domain-verification-5z42wx=BPP8FSBGOXJGD2wH147026ERX",
      "onetrust-domain-verification=5322fc89fae740838eee535685a9fe46",
      "nulab-verification-code=po38DELk2wUybx9tqt8l1itaG14rCIRuK1FPGoEFPURa5fi1gF1rTQIxZefWdAfa",
      "_qkllabfm40beybzwddjw021uy90xijb",
      "stripe-verification=bd6f964c54e62df78d79def27c68a2b4af1c0fd24c5cfbd19097c8cb0e3819b4",
      "docusign=870c49f4-6731-4257-a7c8-4772d6d4dc41",
      "vvcdtvzwt07bq628pl7h6sy8bfkkc5cy",
      "cursor-domain-verification-6terpc=DehnlvlE1od64vx2qGjyUz1to",
      "figma-domain-verification=3e347c955c08b17b30e28103a9f755ce4f119f8936bea56b56d05cf609f88a4a-1745856596",
      "atlassian-domain-verification=sM/6A7tL8dzMRpm1KrxPZYnCcXhQqiEJdDjgEfzq7Bjze1IkxLLSHLy92oeUBPsL",
      "pardot1011361=d825a72fd69c0e25f7f62670660ae32a2701e0ee9d280ab006296ed11b058941",
      "676294466-1012188982",
      "pardot1011361=55d052b12751cad0eb2cc7eb9cbee111aed934ab445c2bcdd323bcf7591b8053",
      "globalsign-domain-verification=002EF26EDC67C8BF6CDBC8076E5B62EF",
      "hcp-domain-verification=0e03260bb7505916bfd820706db91216a997647e5a18f72d6a27266a9047d835",
      "smartsheet-site-validation=UN0O6saeN0eC4nwqPk4iRmw7tplSKGNf",
      "apple-domain-verification=UKTR9hD2CBdNapMPHWSIzNhZ76cyAi58RzKRNPjbsVc",
      "bettercomp-verify=d4c92ff7f01512a34088ec632a21c697438ccc389e17e4c0ad4dfb386a74dc89",
      "v=spf1 include:_spfa.exchange.accenture.com include:_spfb.exchange.accenture.com -all",
      "remarkable-domain-verification=a3fa4bc4-194a-434b-93b0-26ad640d766b",
      "atlassian-domain-verification=DIJvpa34BYkIAvV7ZxCb6IOGuU7vvIvop5U6m2j72w9/CqLgzWM9DmG/aJd0C5u7",
      "google-site-verification=ExtHh0dxqS8yolvzCzLiv6B96zJ-K6a2G1aZ1KUSg_U",
      "anthropic-domain-verification-9vqrpf=ishzrUGD7nNGZwFmOqjkx20yQ",
      "adobe-idp-site-verification=228a2025-9a29-4a24-9dfd-4f0b7d1a9416",
      "mixpanel-domain-verify=9603fa0a-c970-4b25-b616-021ec454bfa4",
      "atlassian-domain-verification=sQQk6YxOzvD/debvDHjnRazCDNLZ3S0a0a50paa8T6CyuAb7ItKJmb47bFXKHv4f",
      "TYR9zuQSRR0CXsu3G6bfVwVM",
      "airtable-verification=e15163bb14cd2edb93b1ea662e99ca6b",
      "docker-verification=dddd690d-45c7-4cdc-b2b8-552178bab04e",
      "smartsheet-site-validation=O2hroUlMZMika9SVtaeyJsV4dpf7-Ej_",
      "docusign=e1dd24c3-bc77-412d-ac0a-46a644d9a2db",
      "mongodb-site-verification=cFVXO1EtlHjsZ0uCqBPAVB4DodFYh0wU",
      "stripe-verification=558d0c1464f98248c5bc40f311e16e3119ebf71f40d426e5fed427acb0a8ddbf",
      "onetrust-domain-verification=317d4e96c02745d9a69ecde3a1772bd2",
      "unity-sso-verification=be147dd4-7167-4fa4-9cf6-96d0cd7e9e20",
      "sending_domain1011361=d2c9d723c0cf979a75118da8b54e4c50a364825840c0e68d68b55e054be61935",
      "heygen-verification=rdtxuefxqdg1nxvd7u0985h3obganhkp",
      "figma-domain-verification=f7c08cd51dc05c2d7c362e60c65b5eb0df260db19719137f8f337c5c6a47c05c-1734592139",
      "317d4e96c02745d9a69ecde3a1772bd2",
      "hpe-greenlake-domain-verification=31584f6c626b69415855715435314b4d74475753437831627268786e58793147",
      "extensis-domain-verification=c5767d81-dba4-40e6-b247-bce4ec06100d",
      "4NvLLK5t7rBsujs4vl8VDloZ3mn8L7+67LBKEXUNPPQNlt5lMFpCo2+k2mcJL9EjheiMP3kHyZ+n2UtBLnUS3w==",
      "cursor-domain-verification-j45q7n=TfB5WOfOYVsGgKv1dCP25KUzO",
      "mistral-domain-verification=2139895d79fff1a2ad175fa9bd924a7bedc186e5",
      "paloaltonetworks-site-verification=cb18840bf30df87d765413356307cf22e2b11b3a5fb5f389d828f108ce556d3d",
      "atlassian-domain-verification=59aeShSTbEvs7cB33k4Wsvath8fOirTAy79UnAbOloto0AyhJb41hHFK8SGb8zxF",
      "openai-domain-verification=dv-TYR9zuQSRR0CXsu3G6bfVwVM",
      "facebook-domain-verification=9ydnlipioha0hvzv7f2wk44xgpu829"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;fo=1;aspf=s;rua=mailto:dmarc_rua@emaildefense.proofpoint.com;ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "subject": "countryName=US, stateOrProvinceName=Illinois, localityName=CHICAGO, organizationName=Accenture LLP, commonName=acnpic.accenture.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jan 30 00:00:00 2026 GMT",
    "notAfter": "Jan 29 23:59:59 2027 GMT",
    "san": [
      "acnpic.accenture.com",
      "careers.accenture.com",
      "acnpic-careers.accenture.com",
      "accenture.com"
    ],
    "days_left": 124,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "170.248.56.19",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [
    {
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.accenture.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://accenture.com/"
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
    "lucidlink-verification=21YDN93BQD7FWH7K0D3XDPK2ZW",
    "notion-domain-verification=gnhjuSDWpptmSxIQQ47C0Dp8nXcUME25kMxltXMAmii",
    "cisco-ci-domain-verification=757b62f6f592352dcec308d68d984e829ffc63970f7a5257940",
    "atlassian-domain-verification=7KcyvCxeJOqBY5fwEHdp8/Nmk9RR7Am4Ihf65044gsFaDhwDtT",
    "monday-com-verification=3bD2wbN66_PVrOmLpWA5FS75DF9RC47efxRHg1SkrbQ"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 4732050424296776365611493050598392527,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "subject_dn": "310b30090603550406130255533111300f06035504081308496c6c696e6f69733110300e060355040713074348494341474f31163014060355040a130d416363656e74757265204c4c50311d301b0603550403131461636e7069632e616363656e747572652e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260130000000",
      "not_after": "20270129235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "*/Careers/Registration",
      "*/Careers/Form",
      "*/Careers/Profiles",
      "*/error/",
      "*/loginpage",
      "*/sitecore/",
      "*/BucketContent",
      "*/RedesignBucket",
      "*/core/",
      "*/?sc_lang",
      "*/secure/",
      "*/clients/",
      "*/client/",
      "*/a-com-no-follow-no-index/",
      "*/_acnmedia/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "acnpic.accenture.com.",
      "acnpic-careers.accenture.com.",
      "careers.accenture.com.",
      "accenture.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.accenture.com/",
    "http_status": 302,
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
    "hsts": "max-age=31536000; includeSubDomains",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "cipher_ver": "TLSv1.2",
    "root_status": 301
  },
  "elapsed_s": 52.0,
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
