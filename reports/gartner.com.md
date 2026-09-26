# Security Audit Report — gartner.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gartner.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | gartner.com |
| Test date | 2026-09-25 17:52 UTC |
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
      "mxb-0016aa01.gslb.pphosted.com (pref 10)",
      "mxa-0016aa01.gslb.pphosted.com (pref 10)",
      "mx0b-0016aa01.pphosted.com (pref 5)",
      "mx0a-0016aa01.pphosted.com (pref 5)"
    ],
    "ns": [
      "pdns77.ultradns.com.",
      "a3-65.akam.net.",
      "a1-109.akam.net.",
      "a5-64.akam.net.",
      "a14-64.akam.net.",
      "a28-65.akam.net.",
      "a4-64.akam.net.",
      "pdns77.ultradns.org."
    ],
    "spf": [
      "prowly-verification=0a18c790f75457f4100202545f5060298b4099a9f9ad953a6f2cd406187d096e",
      "google-site-verification=aKIAxvYjZsxgy4fvr3ys8D_D4naYE21UpdGV3jKNbb0",
      "docusign=176ba6ee-d141-4b4f-951f-ed65844926a4",
      "apple-domain-verification=k0GE0BCT91wGwIyD74bKOw2pu76vgckNG8XTkpxj93w",
      "v=spf1 include:evspf1.gartner.com include:evspf2.gartner.com include:_spf.salesforce.com include:spf.mandrillapp.com ip4:8.15.203.113 ip4:8.15.203.114 ip4:8.15.203.115 ip4:8.15.203.116 ip4:148.59.100.16/28 ",
      "ip4:216.221.170.72/29 ip4:216.221.170.250/31 ip4:216.221.171.8/29 -all",
      "docker-verification=0894b02a-7530-4d69-a114-b173e16374f7",
      "drift-domain-verification=84b976bbb9c08c9f8507ed99d05493997c0f91557421b746b4ef017d64d036b6",
      "docusign=1b2f90f6-48c2-4394-8d1d-bf2ede024866",
      "ciscocidomainverification=57f18449faaaa96630528f3cab6ca711051e21cb8aecdd166f57444d93b57c5",
      "webexdomainverification.FZF7=b569771f-24c7-4cd9-b087-75b779846dde",
      "atlassian-domain-verification=8jqx2ryRUppyajabhJkDQFuiurOAJuQysDFi/wyqM11w4JVloZs9oKlFWUg0RFcu",
      "00DRu00000RGlmb=1TBRu00000014kj",
      "ZOOM_verify_ccu8Ucbb3XjDVqaWJxKT5F",
      "docusign=fbd0b5e3-fd26-4058-a01e-f3231247d403",
      "00DEm00000SNtEz=1TBEm0000000wjx",
      "canva-site-verification=NiX71ocXK6Nit9EcqeZZ_A",
      "paloaltonetworks-site-verification=89f74fa49f2affd44039a4cfce3efa8b83e2eee7d8f52ac84ce59d7a6f41ebb4",
      "uber-domain-verification=db80ddee-dc1a-47b4-b0f9-5382e61b8cc7",
      "hWbBxLhyKc36IrHY2zusOB2kDAgSqdhLvJAxHo7pCUBuRh8ZpBeGKBbQix2ic6FerMsaTaiZY4gzCVnjOpqaNw==",
      "onetrust-domain-verification=9615d0536ed947b2bde2aff220e66c8b",
      "x98FvuwX6an-AAO7F0eMahTQny_-",
      "slido-domain-verification=ca6c3a71-8061-4091-8dac-a342e0bd8e4b",
      "anthropic-domain-verification-ednxat=IQ65KbsWwqCgfrFDGjU3Dox5R",
      "00DD20000003MjH=1TBD20000004CBs;00DEa00000R3lsT=1TBEa0000000PWH;00DD40000009zec=1TBD4000000000v",
      "onetrust-domain-verification=5b726d00265b47399bae397d6aa108eb",
      "lucidlink-verification=8CP62E0W0ET4MRZQS36V2YH1P8",
      "openai-domain-verification=dv-1CqASnTt5JNxuOGMkbJziedR",
      "google-site-verification=npR9iwOMNUbkau8Pwvd4kBqqPDMyXCUu8g5iP1PW_44"
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
    "days_left": 116,
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 15.6,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
