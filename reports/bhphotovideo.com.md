# Security Audit Report — bhphotovideo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bhphotovideo.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | bhphotovideo.com |
| Test date | 2026-09-25 08:06 UTC |
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
- **Detail:** TCP connect to 104.18.39.228:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.39.228:8443 succeeded (state-only check, no payload sent).
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
  "domain": "bhphotovideo.com",
  "dns": {
    "a": [
      "104.18.39.228",
      "172.64.148.28"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx0a-001d5301.pphosted.com (pref 10)",
      "mx0b-001d5301.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns58.ultradns2.com.",
      "ns5.bhphoto.com.",
      "ns4.bhphoto.com.",
      "ns6.bhphoto.com.",
      "ns58.ultradns2.org."
    ],
    "spf": [
      "MS=ms36611676",
      "4FVT4g7h1qNuvYP+SBrngIiVGT3vwF/OssfteNeqLJy48hgiJfzbHnQx8J0PXj2DbJ5C8DfQxHE7ZElzMtTKNg==",
      "qqb1j1puxasmaw8ycweiwswma",
      "google-site-verification=cJbRUei5-m9qImSL5Naf_cWSpJi65F5ggoACxJs2u4g",
      "google-site-verification=qgODUbyk6LIKg-AeUH2caD_Hz-8_t5nfT6PaW2IjKKo",
      "_p91m5ct32bxkskk05tezadqdj5xxgku",
      "5075stzl3wouco6iqqwkusc40k",
      "2xlblhcctcqoyaaqwmwuki4k8m",
      "3tctgcxzdy0qwcwgauo2gqami6",
      "uvit5+LeMJNCTo/NbM5kJDyINuEboKF/sGOhyft+iwjzHeLj0RQS87bjlku+5IWErITOZ1XYT8cEHz3t7lIcMA==",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all",
      "google-site-verification=SjDM75L0fi5kfL9bFa6osbV0j55yZYMz0kJf3dXmGXI",
      "8957003",
      "_globalsign-domain-verification=BahbT-Pu-HaLP9bBimZ0MGe-4CPc4Z_MXqKNUajBmF",
      "google-site-verification=LN8XS_zvsH-V5jCNXi_d-_fyopmv6JjmSQ9CRHURBC0",
      "3w1ub9htry2qes2ygskuii6u0w"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; adkim=s; aspf=r; fo=1; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=bhphotovideo.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Aug 27 11:13:25 2026 GMT",
    "notAfter": "Nov 25 11:13:24 2026 GMT",
    "san": [
      "*.bhphotovideo.com",
      "bhphotovideo.com"
    ],
    "days_left": 61,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.39.228",
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
      "domain": "bhphotovideo.com",
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
      "origin": "https://sub.bhphotovideo.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://bhphotovideo.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 301,
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
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 129.8,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
