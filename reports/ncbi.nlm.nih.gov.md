# Security Audit Report — ncbi.nlm.nih.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ncbi.nlm.nih.gov/ |
| Bug bounty program | U.S. Dept of Health & Human Services (HHS) |
| Listed scope domain | ncbi.nlm.nih.gov |
| Test date | 2026-09-25 10:03 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: clear
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Apache
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "ncbi.nlm.nih.gov",
  "dns": {
    "a": [
      "34.107.134.59"
    ],
    "aaaa": [
      "2600:1901:0:c831::"
    ],
    "cname": null,
    "mx": [
      "nihcesxway5.hub.nih.gov (pref 10)",
      "nihcesxway2.hub.nih.gov (pref 10)",
      "nihcesxway4.hub.nih.gov (pref 10)",
      "nihcesxway.hub.nih.gov (pref 10)",
      "nihcesxway3.hub.nih.gov (pref 10)"
    ],
    "ns": [
      "dns1-ncbi.ncbi.nlm.nih.gov.",
      "ns3.nih.gov.",
      "ns.nih.gov.",
      "ns2.nih.gov.",
      "lhcns2.nlm.nih.gov.",
      "dns2-ncbi.ncbi.nlm.nih.gov.",
      "lhcns1.nlm.nih.gov."
    ],
    "spf": [
      "google-site-verification=nMmA8DdB_FATP9hChkks7To1ndl-jGwVn624WV03SJg",
      "5ongv773afed7ghag3eubs9v6c",
      "21mn4fyhz69y985h80bcyrf4vjqjl0ln",
      "+UYkiJ9LhpTEGd+XduX0MaAclYq9qoJF4Ls5FJaAwl6LRx4aozocl8ZRea9MKMRaquSBJaZC52liuRb0rkxAMA==",
      "v=spf1 ip4:130.14.26.0/25 ip4:165.112.9.132 ip4:130.14.19.0/24 ip4:130.14.28.0/24 ip4:10.65.8.60 ip4:130.14.22.0/24 ip4:128.231.90.64/26 ip4:165.112.13.0/26 ip6:2607:f220:0404:8104::0/64 ip6:2607:f220:402:1a01::0/64 ",
      "ip4:63.150.153.0/28 ip4:63.236.109.192/28 ip4:63.236.97.64/27 ip4:66.77.66.64/26 ip4:63.236.105.192/28 ip4:63.236.106.128/27 ip4:68.177.111.128/26 ip4:156.40.79.128/25 ip4:165.112.194.0/25 ",
      "ip6:2607:f220:041e:4260::41/64 ip6:2607:f220:041e:4260::42/64 ip6:2607:f220:041e:4260::15/64 ip6:2607:f220:041e:4260::16/64 ip6:2607:f220:41f:4260::132/64 include:nih.gov -all",
      "google-site-verification=r_gJSAUUa9jLHjrDalVHx6YDW-U-bIXvV5RAq4l1BEI",
      "64ae187888c443b49126410c89e19f91",
      "6ochlmevf91qg4f4aq6bo33ofk"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:8idhoybh@ag.us.dmarcian.com,mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:8idhoybh@fr.us.dmarcian.com; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.ncbi.nlm.nih.gov",
    "issuer": "countryName=US, organizationName=GoDaddy.com, commonName=GoDaddy TLS Intermediate CA DV - R1v1",
    "notBefore": "Aug 28 16:31:19 2026 GMT",
    "notAfter": "Mar 14 16:31:19 2027 GMT",
    "san": [
      "*.ncbi.nlm.nih.gov",
      "ncbi.nlm.nih.gov"
    ],
    "days_left": 170,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.107.134.59",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "National Center for Biotechnology Information"
  },
  "mixed_content": [],
  "tech": [
    "Server: Apache"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.ncbi.nlm.nih.gov",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ncbi.nlm.nih.gov:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 57.7,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
