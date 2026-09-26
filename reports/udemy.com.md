# Security Audit Report — udemy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://udemy.com/ |
| Bug bounty program | Udemy |
| Listed scope domain | udemy.com |
| Test date | 2026-09-25 10:25 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.142.237:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.142.237:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "udemy.com",
  "dns": {
    "a": [
      "104.16.142.237",
      "104.16.143.237"
    ],
    "aaaa": [
      "2606:4700::6810:8fed",
      "2606:4700::6810:8eed"
    ],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx2.googlemail.com (pref 10)"
    ],
    "ns": [
      "pete.ns.cloudflare.com.",
      "anna.ns.cloudflare.com."
    ],
    "spf": [
      "stripe-verification=e006b01ab77ebbe2e6c509a4e2280540bfea979f8c49ed3efd225004aa2f6292",
      "_nbghqs48lzt0emavhip5o2dyy5kb0xy",
      "globalsign-domain-verification=fB1XzR_1Hvbw32pP6EbLFlB9r4pxcc86XOgA7B7DyV",
      "stripe-verification=5808adfa0c91e8dfe4ecd14f20c22ba0d54b6e8b71b23a5eada978511a246e1a",
      "globalsign-domain-verification=Bo6R5k9s2Zwdk5OoeybGk6L2EHx_oV1TqLgGiMR4IQ",
      "google-site-verification=FZsUD-xuwip73XO7XfuX-4kDEY-_Qel0klHmmu6CB5k",
      "stripe-verification=a4f63d60cd50bfe9f3b2c2d8aa55bc596a98ab6e0f0f2e9d798c6939ece90b90",
      "docusign=d078f828-536c-4ce3-a867-b26ad811bb8a",
      "google-site-verification=ld8CL_RjIj_FPsIdElHPqkhOMJ8Rixk1y7-s0Opi-90",
      "pendo-domain-verification=595ba9d5-03ac-4aee-b50f-168214b6a32a",
      "citrix-verification-code=6b798901-86c6-452c-a3ea-ed718cab39bd",
      "jamf-site-verification=L9yfsaaKM7FxdBtc5kWk6g",
      "atlassian-domain-verification=YpSV2agr6k+w5lkm2ml8m8/N+xCTPcXjTKwDomeoJJTrgnmCoeRyXs/U576G4Cz2",
      "stripe-verification=54fa1ebf13b6990c87e17caffc4829d9600d3bd0ca60b24e6bf9ae530baf37f3",
      "mint-mcp-domain-verification-3p7dva=FgfX3ooe8zSPrzYaM0SEJjugO",
      "stripe-verification=044c7ed24abd68184b0a86b00dbd47b87d1db3a5eb2ee132df5131bfc6fe29d1",
      "apple-domain-verification=MntOsncD5C5BxosV",
      "google-site-verification=mSmGycRVFusrCec4blSh608oUai-y0AumEuI3OlaGBo",
      "google-site-verification=4E_wLzpH4XLGfUSem4QVA6mUpRJDjvZ03pG1jU56hNM",
      "stripe-verification=e2909d7f06f271e18ace56ef06db7b552e6692c312adfedaf6cea1a2e0d63125",
      "google-site-verification=lKnsAORvM6iM1XErS9RH0TeVGG7VfTb5ST7PGx1AQ-w",
      "prowly-verification=bebd281d32a3e1b8140345e1f876f82eff2ba617d782c6206e7c21fd9fdbd880",
      "onetrust-domain-verification=2a6df466515246c4a7c37104f55a82b8",
      "google-site-verification=c7RTHsaBu_LU5KgIFuPCWa5yxuTrkOGYtKaYt85mrq8",
      "google-site-verification=KR2k8MUNPfIO05_bn2-YYMLxVUsnkD-ptX-lBLPmz6M",
      "google-site-verification=IKMJeRfamsooHAMaTQdFDaQ4MsfeW1Nr6F7DPDEkycg",
      "miro-verification=f165badb21a511b048a7f7a9fba3352c0db8b09b",
      "adobe-idp-site-verification=e54c98a1c7f23b54b8ac4b7b75952259c173d7bfba731f72db60eb7ad4e63d97",
      "stripe-verification=8ad760d1d60c9bbd83b03ed7fe20a10682f7d65774aa9db13a0b524e51cefe2c",
      "canva-site-verification=Ng9bmmu7vJyWHYrTk_wUZw",
      "MS=ms39886121",
      "_globalsign-domain-verification=9UioyPO0_F2Epyd3gGV5_VklXzoibTukD_jkbZPw43",
      "stripe-verification=4d955ddab5b0fc6cf1931b41935e45f7997f3b13677532d11e6a90b58f5156aa",
      "globalsign-domain-verification=K9ZBZYNiNsNNOiaY2Tbjn-Bfe0dWwAwpstKoOOVJWO",
      "loom-site-verification=f173ba1cc44648d0ac2bbd0919868a6b",
      "google-site-verification=Ca1sgMRin5VW1yxjUntivQ3-RySo8SmJcWR6zgFW_w0",
      "cursor-domain-verification-pae8cg=8gFowcF4OpBSeYJTIw0GYPFvL",
      "twilio-domain-verification=8e64b1bb044ab98ebbd3638c1babb25a",
      "atlassian-domain-verification=iztR9OQCHGIVBm5w5PmFPf1nTaqiOROSuNTF9Kv0idnfzCBmAsbfwGEF2aOK+yo4",
      "apple-domain-verification=IEscmDl7jHBZDO_dBAG0xMjbBbPxomU_9rqwksKrNmk",
      "google-site-verification=RuYIvfeP5e2eBgQzIaky9XuiCkkrVE2KUBULndTtFE4",
      "openai-domain-verification=dv-ncbISx7kF83lZ69Xc97AoraD",
      "anthropic-domain-verification-8xcn1b=XJ2EZ4D0KXPEyEAZU21FX1D94",
      "v=spf1 include:_spf.google.com include:mktomail.com include:spf.mtasv.net include:mail.zendesk.com include:_spf.salesforce.com -all",
      "_globalsign-domain-verification=oJsQtL3M8axaRGjlRJ4BstY+1TfWDryoeAouwRxay7A=",
      "docusign=206e891a-5b22-4d4c-9a10-85066ba89160",
      "zero-path-domain-verification-6e9hdw=BtrY4vZKLJdp2XlFj1sE4FFVG",
      "cloudhealth=8d6a3d7f-ed91-4280-8422-b4b27b3dfcda",
      "google-site-verification=0Gl3_FzqmUkS2NHg_Wd5pmGiSmt_Jk4MVnaCiDbhDnY"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-udemy@udemy.com; ruf=mailto:dmarc-udemy@udemy.com; rf=afrf; fo=1; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=udemy.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 11 02:43:04 2026 GMT",
    "notAfter": "Dec 10 03:43:02 2026 GMT",
    "san": [
      "udemy.com",
      "*.udemy.com"
    ],
    "days_left": 75,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.16.142.237",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "udemy.com",
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
      "origin": "https://sub.udemy.com",
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
  "elapsed_s": 24.9,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
