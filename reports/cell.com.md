# Security Audit Report — cell.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cell.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | cell.com |
| Test date | 2026-09-25 07:58 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | CT1 | 14 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.66.0.112:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.66.0.112:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=2592000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] 14 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: staging.www.cell.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "cell.com",
  "dns": {
    "a": [
      "172.66.0.112",
      "162.159.140.114"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "cell-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns1.reedelsevier.com.",
      "ns3.reedelsevier.com.",
      "ns2.reedelsevier.com."
    ],
    "spf": [
      "miro-verification=edd5a54fc20add96505c5c718975977b28f370a9",
      "ZOOM_verify_W4AuTEx9ROGD4kK_ePkcBA",
      "NNaG7DvrFpIe+hqV6axdB2BDDbaBT5OUuQ8dl5fRyvYVFnuNb39lU9OREInFizJw5B3FZ91RQjKgRLOa+7BJXA==",
      "adobe-idp-site-verification=fd4fae74b683e6e22ef9b491871ae9f0faf7856b8a8588d267e24565628d2dbd",
      "v=spf1 include:spf.protection.outlook.com include:519224.spf06.hubspotemail.net ip4:202.54.185.101 ip4:210.18.134.82 ip4:202.54.183.83 ip4:203.129.255.210 ip4:122.187.94.54 ip4:115.110.117.138 ip4:103.130.89.242 ip4:47.247.140.234 ip4:47.247.140.230",
      " include:rnmk.com -all",
      "onetrust-domain-verification=509af418dcce43c5a6330cd2128ee529",
      "MS=ms13784580",
      "anthropic-domain-verification-ssq6py=6YMLbUb5ERHhYY7Heuk7JKNHt",
      "pendo-domain-verification=f1e205fa-06f4-4a13-a73a-3e0f82e7f104",
      "atlassian-domain-verification=2ckcJUmjEfh8TAauQPrWb9eLXpM1UyNHPk+6SmzC3X0tqBzJKZFYmm9rbKXfVm0v",
      "onetrust-domain-verification=703cad9baa55456ab0ed05c40cd00445"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:reed-elsevier@rua.agari.com,mailto:dmarc-a@elsevier.com; ruf=mailto:reed-elsevier@ruf.agari.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=cell.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug  7 19:46:31 2026 GMT",
    "notAfter": "Nov  5 20:46:29 2026 GMT",
    "san": [
      "cell.com"
    ],
    "days_left": 41,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.66.0.112",
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
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.cell.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://cell.com/"
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
    "/.well-known/security.txt": 200,
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
    "source": "certspotter",
    "count": 14,
    "notable": [
      "staging.www.cell.com"
    ],
    "sample": [
      "advertisers.cell.com",
      "cell.com",
      "cellreports.cell.com",
      "crosstalk.cell.com",
      "embargoed.www.cell.com",
      "info.cell.com",
      "preferences.cell.com",
      "recruitmentads.cell.com",
      "snapshots.cell.com",
      "staging.www.cell.com",
      "stemcellreports.cell.com",
      "www.advertisers.cell.com",
      "www.cell.com",
      "www.recruitmentads.cell.com"
    ]
  },
  "elapsed_s": 127.9,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
