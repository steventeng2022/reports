# Security Audit Report — ibm.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ibm.com/ |
| Bug bounty program | IBM |
| Listed scope domain | ibm.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 5, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 22 days (notAfter Oct 17 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=3600 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "ibm.com",
  "dns": {
    "a": [
      "184.84.207.120"
    ],
    "aaaa": [
      "2600:1417:8400:17b9::3831",
      "2600:1417:8400:1782::3831"
    ],
    "cname": null,
    "mx": [
      "mx0b-001b2d05.pphosted.com (pref 5)",
      "mx0a-001b2d05.pphosted.com (pref 5)"
    ],
    "ns": [
      "dns4.p05.nsone.net.",
      "dns1.p05.nsone.net.",
      "dns3.p05.nsone.net.",
      "dns2.p05.nsone.net."
    ],
    "spf": [
      "coursera-domain-verification=To0Ej5CrewXrC0FcCjVxXG1lTcLLJQjvrW2gdUt8rCxFxTGMdA0vA54nUlgLfbyO",
      "00df40000004784eaa",
      "google-gws-recovery-domain-verification=48225137",
      "40a21f5affe343c6b37e0a5af80dcd93",
      "docker-verification=7c4d4e40-e7ee-4183-94c2-db97d0873269",
      "jamf-site-verification=CN4bHigc1ZnD6ZQX_2c6XQ",
      "figma-domain-verification=b8b3862b529816383e0e7ec9ad2757f8f7b4a0f4da290136796f1aa36d558841-1785230801",
      "google-site-verification=Jck8mLbYYfCnrmi_nRy4MG2fbUN3UGhC29KdspGLd9Y",
      "atlassian-domain-verification=79ZnqmRPyDwm6b99GAF3ymzBmjtRZU9oCfgMwVMAUGlrPPenDc6esgO62jafAXUI",
      "apple-domain-verification=M3o953J0rN1B0P2a",
      "google-site-verification=aH5jG_abrxRKeKZKOrX9CuXlXdFSCQxVkmAVoYwzNcc",
      "DomainVerification=CYICZMSWT62KDTQWZ1YCKKU763NN36BQJ4TD5BV606K3FLDUR3UOJE58E30FTIVL",
      "amazonses:79ShwQazteb+WkCt8e297sAC2mwZVRditsrzaoxiHjU=",
      "adobe-idp-site-verification=5f8adca7-512f-44e1-a5b2-b62c5e3763f2",
      "MS=ms61389031",
      "h1-domain-verification=m9jGKLYa5hDdU5AHUfK9jrBmWVhx3h9t9ztfDFMaxZfgChvk",
      "00d50000000c9mweay",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all",
      "smartsheet-site-validation=TaCpXPZ-qFfOgfHXuMrfF8_d6GZjICNl",
      "atlassian-sending-domain-verification=79afa9af-6e0f-47e6-b636-2786f8772f66",
      "00d00000000hedieay",
      "google-site-verification=tzdngH5fWH-k8uQoDVovOFJQZTwaGtDOP6S2cQlOvCs",
      "atlassian-domain-verification=WAjTH82C5Zx475WLKAA2nrdlsoA/kN0ej9igrLrED4h15KMHPOm+A5H3GndKAxDC",
      "figma-domain-verification=6db9259c4472f3e5ba44c7ae284b4f4b8aa0268c0797659a5e1a28ccfe912ddf-1741206863",
      "google-site-verification=ewe2QcP5aMj3DKuSfxscZME5wip4EpoTxCXPNvr0-J0",
      "google-gws-recovery-domain-verification=42135076",
      "yandex-verification: 5f458b477256c50c",
      "ms-domain-verification=bedcd06e-7e1c-4906-9b6a-b4a1095fa4ed",
      "asv=e8bb80eeac60e62a4dd07f03d1d36829",
      "_github-challenge-ibm.ibm.com=2613e984bc",
      "_analyst_ng_validation=f6702989-83f3-42b8-be39-19cf8f1c33f5",
      "mongodb-site-verification=Gcqpap80hVonXfV2VnYC6AlEr2Z9vvf3",
      "00D3h000004YkeYEAS",
      "ms-domain-verification=1adbc779-89ce-47cf-8167-c4e4a3b4a6aa",
      "atlassian-domain-verification=a32Aj0uoXQRh6QseDFFrlufYlkbeSdok7az3sY0DQNVXpW1Iqj8zlsuXFZgHMojH",
      "docker-verification=846278f4-7e2c-4586-ae26-e1a9f0f0aecd",
      "facebook-domain-verification=7w4exj2revwpv5u708s6bji5j6tswy",
      "intersight=1439768961d2f6d736c38b947d235947681cd817abea13eab3daee9ecbdc6c3d",
      "google-site-verification=I-empodMpM7n5Px1doUgIaOKHKeIMXXf6k8Ea5ENyO4",
      "Dynatrace-site-verification=76b6b299-fe43-4f31-889b-a8a467193478__8q74sg9dg5udjppn95utrb8bct",
      "smartsheet-site-validation=I-lI3gCPdvKbKQ6KTki96Ream6Yjs1gU",
      "intersight=cfe6f48b59e7428442b9aab04765ca0953e01c480a685ca5cf6939ef9e505532",
      "mongodb-site-verification=gEevYaKFpagtLmrYxomtpE2QmYwnd29i",
      "onetrust-domain-verification=e7e09cedfb9b4ff386f1274e4c214d55",
      "wework-site-verification=hhWLSbG4qiaKhsXU",
      "00D10000000biEb=1TBQ80000000b2n",
      "anthropic-domain-verification-ym2t7s=RPDdVAMpzgbooX0kxhqstuM2D",
      "mongodb-site-verification=3d0wR0KvanH3yTbll0sXEJ0QGBQffOkv"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=none; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=Armonk, organizationName=International Business Machines Corporation, commonName=ibm.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Oct 17 00:00:00 2025 GMT",
    "notAfter": "Oct 17 23:59:59 2026 GMT",
    "san": [
      "ibm.com",
      "asmarterplanet.com",
      "blog.turbonomic.com",
      "bluewolf.com",
      "heal.ibm.com",
      "heal.ibm.org",
      "ibm.org",
      "ibm.ua",
      "ibm100.com",
      "ibmbigdatahub.com",
      "lendyr.com",
      "maas360.com",
      "sevone.com",
      "turbonomic.com",
      "www.asmarterplanet.com",
      "www.bluewolf.com",
      "www.ibm.com",
      "www.ibm.ua",
      "www.ibm100.com",
      "www.ibmbigdatahub.com",
      "www.lendyr.com",
      "www.maas360.com",
      "www.sevone.com",
      "www.turbonomic.com"
    ],
    "days_left": 22,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "184.84.207.120",
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
      "origin": "https://sub.ibm.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ibm.com/"
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
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 24.7,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
