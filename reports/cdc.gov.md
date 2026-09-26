# Security Audit Report — cdc.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cdc.gov/ |
| Bug bounty program | U.S. Dept of Health & Human Services (HHS) |
| Listed scope domain | cdc.gov |
| Test date | 2026-09-25 08:57 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "cdc.gov",
  "dns": {
    "a": [
      "23.210.215.218",
      "23.210.215.203"
    ],
    "aaaa": [
      "2600:1417:76::17d2:d7cb",
      "2600:1417:76::17d2:d7da"
    ],
    "cname": null,
    "mx": [
      "alt2.us.etp.fireeyegov.com (pref 30)",
      "alt1.us.etp.fireeyegov.com (pref 20)",
      "alt3.us.etp.fireeyegov.com (pref 40)",
      "primary.us.etp.fireeyegov.com (pref 10)"
    ],
    "ns": [
      "a8-67.akam.net.",
      "a9-64.akam.net.",
      "a5-66.akam.net.",
      "a28-65.akam.net.",
      "a1-43.akam.net.",
      "a2-64.akam.net."
    ],
    "spf": [
      "apple-domain-verification=VOKePKhT9MhX9zmq",
      "identrust_validate=B/Pm/IvNx8tLDDFRsJXBs+oweQGmx08QZ6xK0IvBQn3R",
      "268BC041572123F15C5566E5F3D88675FABCC028427B501AE228CA9BB31630D5",
      "MS=ms84056562",
      "_v0e31vq52ru6qgumyh95pylxoe5kmby",
      "atlassian-sending-domain-verification=977cbfcd-c314-42dc-9d86-32e2abca00ac",
      "atlassian-domain-verification=qjHCJ33pyZHmggxdcFDtGiegrc/iLSyVUIG0LAu1g7XW1JnMdaY8G8pbMUY1Z4hm",
      "adobe-idp-site-verification=4089552e88740d878b0400d184ab01c0b7391e6dc85796732000450e3476fc93",
      "atlassian-domain-verification=i5oCgfh8OkdKw7Yv2CCKvAdKMW8kYpNVO1A7fcUkBdAy7IzdP/M8D9NoirnaVqZC",
      "v=spf1 ip4:51.5.72.0/24 ip4:172.81.81.38 ip4:51.4.72.0/24 ip4:51.5.80.0/27 ip4:51.4.80.0/27 ip4:172.81.81.50 ip4:172.81.82.50 ip4:63.123.152.4 ip4:40.92.0.0/15 ip4:172.81.82.79 ip4:172.81.80.64 ip4:172.81.81.39 ip4:172.81.82.87 ip4:172.81.82.88 ip4:155.95",
      ".96.50 ip4:155.95.86.50 ip4:23.90.98.102 ip4:124.17.27.36 ip4:149.72.0.0/16 ip4:198.21.0.0/21 ip4:50.31.32.0/19 ip4:167.89.0.0/17 ip4:68.232.140.57 ip4:68.232.140.79 include:_s0.cdc.gov -all",
      "google-site-verification=nZIK8Rc0sw4MxlgnsYseSBTdcyDXeLFR6P5FIAbgSEM",
      "geneious.com:domain-verification=DP8tae0qCr-FH6KGRvMwWA",
      "v4ixju/hXVFXszYswwinkbStpHoDb361lQekI6rkjQ2DV4HHKdN/FJPvMAO88x1rTaRwf29UYwPAq6LqldNWZQ==",
      "atlassian-sending-domain-verification=a39e7003-10de-46b1-8afb-86ef7509f246",
      "dtm-domain-verification=KQ1rIgUP8GpiV9mSmysS40YKtHjVrI0VF938cuCAWXQ",
      "_mhpeli9n9zj3rasw6wfiuch30t2sjlw",
      "amazonses:OhxI8Nxovqf1xBmhK5S9kNk7vo9XV4GmGe6LVc+ji80=",
      "google-gws-recovery-domain-verification=42225222",
      "ZOOM_verify_yEK5MgTwT72nP5URz-eoaA",
      "google-site-verification=GkbnFA_aF3RXaZOC3deEsrGqs0fmTXyys2hbIn1nVcM",
      "_ddb344bjip99et71u5cidtx1t53ezdl",
      "google-site-verification=qZbBdujV5kZQv_pCqV2wpfSU25odH35HQukm5ACyLNs",
      "openai-domain-verification=dv-hbgCCuVm9CpZSVXjvFPfivD5",
      "4FF7-1931-E8C2-912B-94CF-BCB0-806A-7442",
      "atlassian-sending-domain-verification=f2ef9649-6a78-47f6-9990-44a295ae5b5a",
      "_bthbaxy8p6mr5c0o5r7pit3d25lgztb"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; ri=3600; rua=mailto:8idhoybh@ag.us.dmarcian.com,mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:8idhoybh@fr.us.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=Georgia, localityName=Atlanta, organizationName=Centers for Disease Control and Prevention, commonName=*.cdc.gov",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Sep  2 00:00:00 2026 GMT",
    "notAfter": "Mar 19 23:59:59 2027 GMT",
    "san": [
      "*.cdc.gov",
      "cdc.gov"
    ],
    "days_left": 175,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.210.215.218",
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
  "cookies": [
    {
      "domain": ".cdc.gov",
      "samesite": "none"
    },
    {
      "domain": ".cdc.gov",
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
      "origin": "https://sub.cdc.gov",
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
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 84.9,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
