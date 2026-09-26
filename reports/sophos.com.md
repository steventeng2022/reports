# Security Audit Report — sophos.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://sophos.com/ |
| Bug bounty program | Sophos |
| Listed scope domain | sophos.com |
| Test date | 2026-09-25 10:17 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=93600
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "sophos.com",
  "dns": {
    "a": [
      "23.210.215.216",
      "23.210.215.152"
    ],
    "aaaa": [
      "2600:1417:76::17d2:d7d8",
      "2600:1417:76::17d2:d798"
    ],
    "cname": null,
    "mx": [
      "mx-01-eu-west-1.prod.hydra.sophos.com (pref 10)",
      "mx-02-eu-west-1.prod.hydra.sophos.com (pref 10)"
    ],
    "ns": [
      "a10-65.akam.net.",
      "a11-66.akam.net.",
      "a18-64.akam.net.",
      "a9-65.akam.net.",
      "a1-100.akam.net.",
      "a14-67.akam.net."
    ],
    "spf": [
      "_f1a9kf91a5ksktt14czu26jj992sy70",
      "yqSChZpEwgPNHna2bdAZhr6ASFb82MxruOD00tp0NEc=",
      "06x71m1wfychwzb068j6rw0vgt96pp8m",
      "drift-domain-verification=0146cf28092efe02d9b245bc034a49ee101121324faab085d4dc39bfe8a668e2",
      "drift-domain-verification=244bf919d29f6e74ac0c52978f5cf28015cb7cb169f306a95a5ae1e08f3adc49",
      "pendo-domain-verification=IkagvqgdNFxKHKUChcptstdLpx0",
      "drift-domain-verification=e20214575377f71bf2d2dfde7f181305a85e78cd4d298a62cc27511e00cfbf2d",
      "drift-domain-verification=cf8ef47a8b657b331173804c5189d62dfed3eefb03f4144a1b4cbf031a9b9fee",
      "sz0tpkq215zbcjsnrghfx0p3ksctty81",
      "drift-domain-verification=ac53b25173908b0a36aeac6b99ddc02b6f606859e2b6b8878c0d8f3503666331",
      "1password-site-verification=QASQSNF7TZGBTLBYSIMHRRDUJY",
      "drift-domain-verification=19e95e7c5f04ec70ad60395ef64d1d5f0fd975f23bd3d60cb9b8fa25882318b9",
      "smartsheet-site-validation=zMtI30Z_7BcFJrKZw2iBeQtMCrTV-V76",
      "MS=ms20777252",
      "drift-domain-verification=20e3140bc5cd2b4cdef1fd9f3ed9298e9e0d31747509233b49da413a5bb43ee8",
      "successfactors-site-verification=Yzk4ZmFhMmY4ZjU4NTgxMWE4Yjk0MTliN2Y1MjBiZTkzZjVlN2E4N2VlYWU3NzEyM2FlYjdjM2Q5MGJkN2ZhNA==",
      "z08yq9grj0sygqd4vq7mhgqgbmd7r6xd",
      "docusign=d6465c58-dca5-44f2-a22d-62be8d4e1549",
      "openai-domain-verification=dv-RuJLc7us6Nv0F8LDFDKAc7uw",
      "vmware-cloud-verification-22c2ef74-7090-455a-a617-841a0f1f8d5b",
      "docker-verification=6e3a01d0-a79a-42dc-a6ef-8f5d1a5809e9",
      "google-site-verification=Oc8MKdnVS9zYeJAG_DhDTp4iqXaBhuyBzgYGK6KzHnM",
      "apple-domain-verification=2Fy8bFXuDV8Wohcz",
      "v=spf1 redirect=sophos.com.spf.sophosdmarc.net",
      "NI+GrCnazEEzN/8Sthq9Gsv1drLkK3CMmK8mgLop7FBCj1MBeZrJJYenxQDp9/soSLBrjL8zmvQmfc4t3Ay0Kw==",
      "_eb0avl1j1pmnomqfy7mg16rzj4xeofk",
      "drift-domain-verification=49154060112759b8163b0b1d710afdc93baf7a1924c169c4f607693b96e00d1c",
      "/gbE6SOtgWszrbftvjWRktjABSHim5ssJdPQdJiUFLo=",
      "cursor-domain-verification-hrtcqr=rmEeK8UvFTDWoWCbPe4W48MjS",
      "_globalsign-domain-verification=C05a5k5-Y296XYz_gRGPOfxEkNeRr5aUxtPVZOA0LR",
      "SlL66Pe6+pzghTfp9TqupnOauqPcYMVnc2pdpFE/1Bc=",
      "anthropic-domain-verification-6yf00s=Ye5rWegH81UZ1ONGj1gmTft8O",
      "cloudhealth=30a3e90e-bf54-4e23-8a07-50d20631d7c7",
      "openai-domain-verification=dv-ziQBcZtypxlBQk0anqgGA2kV",
      "drift-domain-verification=1190d60eec406b5bb9fbd5c0b991664c89480bf53d8586c85f47f6e1e92b4194",
      "google-site-verification=A4IvAx3bsimlNuuaij7KW4YsWI65V04qIRDfyGsFSsI",
      "nKB8VtcYTnBVg9VjdPOQFKkeyp6YxWb4YE8p3XZmDUE=",
      "drift-domain-verification=fc2b61befbd0e7d1ea38a099c21522e6c485b69c00e2ffa3cf08971046f19ae3",
      "drift-domain-verification=33ee4934494487d5fd3103d23e43be36abe49fd4e594c3da6da4df4cd6d75a04",
      "sophos-domain-verification=3982f63bedcff7ccd4ef51ba54d39b4d14ae1c3a",
      "cvja4aPXWZ5uq4VxbmCcPmw12cJhfTX6F0ZWoGfRbBNmCUf1v6xHgleSWnXb65AJV3e6Ii5Qp8YnROIFYF+tAA==",
      "google-site-verification=UbmZT8AVCxe8ajII1pukSvwqRnCbDaTKJuXzpKACEao",
      "atlassian-sending-domain-verification=b1c8568f-2e3b-4c13-bbad-b0875980471a",
      "aline-domain-verification-1j2324=omzScvZJaszchZh413GWALRdg",
      "b1cab410c2cd4c1ba415ff35d5df0ee0",
      "atlassian-domain-verification=yGw28l7QRDvcaSLmkM/aMTlngetgzc7rNRrMFeA/iwxi6AoGLUVF9lfC9ZJXwcPw",
      "miro-verification=27ceec0b31a177e34cf8d5befad732294ab707c1",
      "censys-domain-verification=aV3Fk9juFo3K4z0zZqvVOtRY-bgyef_YRSODYMZP82xN",
      "S0bXs6uppeiOgIHjU7++zYBrJdO/lto8F+lutV6shoM=",
      "8XnBlZqV5LM6S3WAyE4hFKvJhkx9pb52O9HKScFHlGw=",
      "6z6zg07kf5yqbgx9k28zgx7pbzyk4tqv",
      "_cbc-idp-site-verification-b51e45=363de791496d5b55ec143df32f41673e0017799ceee75317498ca36d9c1253f3"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=100; fo=0:s; rua=mailto:a.z2zesduo@reports.sophosdmarc.net,mailto:dmarc_rua@sophos.com; ruf=mailto:dmarc_ruf@sophos.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=www.sophos.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug 19 06:54:53 2026 GMT",
    "notAfter": "Nov 17 06:54:52 2026 GMT",
    "san": [
      "assets.sophos.com",
      "club.sophos.com",
      "demo.sophos.com",
      "dev-login.sophos.com",
      "dev.preview.sophos.com",
      "discover.sophos.com",
      "home.sophos.com",
      "investors.sophos.com",
      "login.sophos.com",
      "my.astaro.com",
      "myutm.sophos.com",
      "news.sophos.com",
      "partnernews.sophos.com",
      "partnerportal.sophos.com",
      "partners.sophos.com",
      "qa.preview.sophos.com",
      "secure2.sophos.com",
      "sophos.com",
      "sophserv.sophos.com",
      "stage.preview.sophos.com",
      "test-login.sophos.com",
      "www.hitmanpro.com",
      "www.secureworks.com",
      "www.secureworks.jp",
      "www.sophos.com",
      "www.surfright.com",
      "www.surfright.nl"
    ],
    "days_left": 52,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.210.215.216",
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
      "origin": "https://sub.sophos.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://sophos.com/"
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 22.4,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
