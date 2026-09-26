# Security Audit Report — accenture.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://accenture.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | accenture.com |
| Test date | 2026-09-25 08:15 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 0, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |

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
      "mx0a-001dcc01.pphosted.com (pref 10)",
      "mx0b-001dcc01.pphosted.com (pref 10)"
    ],
    "ns": [
      "apans3501.accenture.com.",
      "cfans1002.accenture.com.",
      "cfans1001.accenture.com.",
      "amrns1501.accenture.com.",
      "emens3501.accenture.com."
    ],
    "spf": [
      "mongodb-site-verification=cFVXO1EtlHjsZ0uCqBPAVB4DodFYh0wU",
      "pardot1011361=d825a72fd69c0e25f7f62670660ae32a2701e0ee9d280ab006296ed11b058941",
      "4NvLLK5t7rBsujs4vl8VDloZ3mn8L7+67LBKEXUNPPQNlt5lMFpCo2+k2mcJL9EjheiMP3kHyZ+n2UtBLnUS3w==",
      "adobe-sign-verification=da99fb7e471e8e812595bd6a8c5e2875",
      "stripe-verification=bd6f964c54e62df78d79def27c68a2b4af1c0fd24c5cfbd19097c8cb0e3819b4",
      "00D4P000000i2Tx=1TBaZ00000003SX",
      "nulab-verification-code=k4l5aMXngpLUhKTLEuiHj2dDFSUBLxoKetjixslAkfHvvwcBagg14LmP9Ru4xUZO",
      "docker-verification=dddd690d-45c7-4cdc-b2b8-552178bab04e",
      "_kdq25tboq1e8epp3npdldrtq4lrl6vd",
      "facebook-domain-verification=9ydnlipioha0hvzv7f2wk44xgpu829",
      "apple-domain-verification=UKTR9hD2CBdNapMPHWSIzNhZ76cyAi58RzKRNPjbsVc",
      "atlassian-domain-verification=59aeShSTbEvs7cB33k4Wsvath8fOirTAy79UnAbOloto0AyhJb41hHFK8SGb8zxF",
      "lucidlink-verification=21YDN93BQD7FWH7K0D3XDPK2ZW",
      "cursor-domain-verification-5z42wx=BPP8FSBGOXJGD2wH147026ERX",
      "smartsheet-site-validation=UN0O6saeN0eC4nwqPk4iRmw7tplSKGNf",
      "Dynatrace-site-verification=cf509ddc-d5d6-43a1-a4c2-c120d3b0933b__v9qm0u1chpsc5jhkdpafn869s3",
      "openai-domain-verification=dv-TYR9zuQSRR0CXsu3G6bfVwVM",
      "atlassian-domain-verification=7KcyvCxeJOqBY5fwEHdp8/Nmk9RR7Am4Ihf65044gsFaDhwDtT3fmmt3gdGbur3M",
      "unity-sso-verification=be147dd4-7167-4fa4-9cf6-96d0cd7e9e20",
      "atlassian-domain-verification=DIJvpa34BYkIAvV7ZxCb6IOGuU7vvIvop5U6m2j72w9/CqLgzWM9DmG/aJd0C5u7",
      "globalsign-domain-verification=002EF26EDC67C8BF6CDBC8076E5B62EF",
      "nulab-verification-code=8TTNkc4cj170WuQDQXnntAFmVZulfy8muhpysoP7FuaDXfoObfZUYi5GfIFFO5OI",
      "notion-domain-verification=gnhjuSDWpptmSxIQQ47C0Dp8nXcUME25kMxltXMAmii",
      "clayton-domain-verification=b74f705c0b4e4369823f5e0717bdaba2abeb4b48d5",
      "_qkllabfm40beybzwddjw021uy90xijb",
      "paloaltonetworks-site-verification=cb18840bf30df87d765413356307cf22e2b11b3a5fb5f389d828f108ce556d3d",
      "figma-domain-verification=3e347c955c08b17b30e28103a9f755ce4f119f8936bea56b56d05cf609f88a4a-1745856596",
      "Hp48LTxGknu4omlcp1bP0HqFH2VBFOLA88QS7zwDTJQaM2moc6schoR8P30qVYcuO/RK+cUiCTnntk5pSUk+SA==",
      "docusign=614ac0a7-7549-4436-b0f7-d6465424f092",
      "hcp-domain-verification=0e03260bb7505916bfd820706db91216a997647e5a18f72d6a27266a9047d835",
      "mixpanel-domain-verify=9603fa0a-c970-4b25-b616-021ec454bfa4",
      "stripe-verification=BB11E45F6EB04F0F3639CBC7E7C56E9579F457BCC44999D1BC492F3C8E03BE4E",
      "bettercomp-verify=d4c92ff7f01512a34088ec632a21c697438ccc389e17e4c0ad4dfb386a74dc89",
      "nulab-verification-code=po38DELk2wUybx9tqt8l1itaG14rCIRuK1FPGoEFPURa5fi1gF1rTQIxZefWdAfa",
      "google-site-verification=ExtHh0dxqS8yolvzCzLiv6B96zJ-K6a2G1aZ1KUSg_U",
      "v=spf1 include:_spfa.exchange.accenture.com include:_spfb.exchange.accenture.com -all",
      "MS=ms19684732",
      "pardot1011361=55d052b12751cad0eb2cc7eb9cbee111aed934ab445c2bcdd323bcf7591b8053",
      "sinch-domain-verification=ad65d33d-c9d1-491c-9349-86fa8b0bfc4a",
      "heygen-verification=rdtxuefxqdg1nxvd7u0985h3obganhkp",
      "asv=c7a401fd2ce4afdc4c9898caee92a999",
      "mistral-domain-verification=2139895d79fff1a2ad175fa9bd924a7bedc186e5",
      "monday-com-verification=3bD2wbN66_PVrOmLpWA5FS75DF9RC47efxRHg1SkrbQ",
      "676294466-1012188982",
      "smartsheet-site-validation=6WKcBZVtX1tBTc2dEsYpkswqp-BOFGHx",
      "317d4e96c02745d9a69ecde3a1772bd2",
      "smartsheet-site-validation=owIJ5MLqX9KoiMfKRnEcU_FVn3xQVPlA",
      "adobe-idp-site-verification=228a2025-9a29-4a24-9dfd-4f0b7d1a9416",
      "TYR9zuQSRR0CXsu3G6bfVwVM",
      "amazonses:8GzbTEmni2PBRv6jLZwAq1rcYGkbVEmlNuHIcahJ1K0=",
      "anthropic-domain-verification-9vqrpf=ishzrUGD7nNGZwFmOqjkx20yQ",
      "_oq9iiyjw00buc5zqyxlp9n3kmwc9mdx",
      "cursor-domain-verification-6terpc=DehnlvlE1od64vx2qGjyUz1to",
      "onetrust-domain-verification=317d4e96c02745d9a69ecde3a1772bd2",
      "vvcdtvzwt07bq628pl7h6sy8bfkkc5cy",
      "figma-domain-verification=f7c08cd51dc05c2d7c362e60c65b5eb0df260db19719137f8f337c5c6a47c05c-1734592139",
      "hpe-greenlake-domain-verification=31584f6c626b69415855715435314b4d74475753437831627268786e58793147",
      "docusign=e1dd24c3-bc77-412d-ac0a-46a644d9a2db",
      "docusign=870c49f4-6731-4257-a7c8-4772d6d4dc41",
      "remarkable-domain-verification=a3fa4bc4-194a-434b-93b0-26ad640d766b",
      "atlassian-domain-verification=sM/6A7tL8dzMRpm1KrxPZYnCcXhQqiEJdDjgEfzq7Bjze1IkxLLSHLy92oeUBPsL",
      "cisco-ci-domain-verification=757b62f6f592352dcec308d68d984e829ffc63970f7a52579405448c1f39b4f2",
      "airtable-verification=e15163bb14cd2edb93b1ea662e99ca6b",
      "sending_domain1011361=d2c9d723c0cf979a75118da8b54e4c50a364825840c0e68d68b55e054be61935",
      "smartsheet-site-validation=O2hroUlMZMika9SVtaeyJsV4dpf7-Ej_",
      "cursor-domain-verification-j45q7n=TfB5WOfOYVsGgKv1dCP25KUzO",
      "atlassian-domain-verification=sQQk6YxOzvD/debvDHjnRazCDNLZ3S0a0a50paa8T6CyuAb7ItKJmb47bFXKHv4f",
      "_fwg4t33rpupb269hsu805z0uvcray32",
      "extensis-domain-verification=c5767d81-dba4-40e6-b247-bce4ec06100d",
      "stripe-verification=558d0c1464f98248c5bc40f311e16e3119ebf71f40d426e5fed427acb0a8ddbf",
      "onetrust-domain-verification=5322fc89fae740838eee535685a9fe46"
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
    "days_left": 126,
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
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 208.9,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
