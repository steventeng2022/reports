# Security Audit Report — linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | linkedin.com |
| Test date | 2026-09-25 09:56 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 0, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 7 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ESF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ESF
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 7. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.linkedin.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

## Evidence (raw response observations)

```json
{
  "domain": "linkedin.com",
  "dns": {
    "a": [
      "130.211.32.14"
    ],
    "aaaa": [
      "2600:1901:0:d5ad::"
    ],
    "cname": null,
    "mx": [
      "mail-a.linkedin.com (pref 10)",
      "mail-c.linkedin.com (pref 10)",
      "mail.linkedin.com (pref 20)",
      "mail-d.linkedin.com (pref 10)"
    ],
    "ns": [
      "ns2-42.azure-dns.net.",
      "dns1.p09.nsone.net.",
      "dns2.p09.nsone.net.",
      "dns3.p09.nsone.net.",
      "ns3-42.azure-dns.org.",
      "ns4-42.azure-dns.info.",
      "dns4.p09.nsone.net.",
      "ns1-42.azure-dns.com."
    ],
    "spf": [
      "google-site-verification=X0LoSQsAMzR-TK4o-ULrYAwLi_fyopfRLkm_C-4N4Ts",
      "apple-domain-verification=Hp7LihDNsREwfHX9",
      "bluebeam-verification=02px6k8snlrzd6gx3b3oqkeatbzawd",
      "google-site-verification=xAGz495k8RbGclhamQx1TkZSHDxOaEd95fOjc8xpbTA",
      "docusign=11f01284-dffc-40f9-8d56-57e5261ede3f",
      "atlassian-sending-domain-verification=3bdb0597-814d-4e10-a552-5cf78f92ab3c",
      "google-site-verification=anx3jpa6VKkTWRJKnglUIzm7UEn-ZCT2WqAfG7h-xOg",
      "google-site-verification=VE9BWhjbPPNmbr3ZJcwn5hLTsz7c5KPt3zXdYyaSnSQ",
      "atlassian-domain-verification=juKdSE4GGphSmzPkhmnRJUNIn0ALdb0vsP7VSPM8TmTP7WgbgUQPLFdNicP7bF58",
      "google-site-verification=vfmYHwjzUIFPzxFcyuwEToh_1kG9wvcpGgJnB-MhQn8",
      "vmware-cloud-verification-f4d7c1c7-ad66-450f-82fa-c17b9ee79459",
      "AFDVALIDATION=LinkedIn",
      "bf5fl8sny79w4c70jxp6cp3crkqtr7qk",
      "google-site-verification=oJFWbtlKRblXs4smNibcoJkTJqwT6gd3XMI80VjBihE",
      "elevenlabs=hRLt8nemUjAWJSL_xhBIsKFyK4yYV089AvwkOB0cxYY",
      "_cthqqp5zj8g86qf3h97heqitg2zc32b",
      "google-site-verification=0Vs9yf1V6RGkuzow85OzIXKEnjpRswpDkI6RgDVspMg",
      "atlassian-domain-verification=dDed2VFvlDajBX8X22w52Jx/W/YLHR81SxUuraa9zNdz4aLjDS/RpfN11w2bxpRc",
      "google-site-verification=8LaIeBMwr6K8qWeaGa4CEmfPKiZDwaT38t5mIrtaroI",
      "miro-verification=260f00146b6d2ad1bb70d6dc07a077b672badd28",
      "v=spf1 ip4:199.101.162.0/25 ip4:108.174.3.0/24 ip4:108.174.6.0/24 ip4:108.174.0.0/24 ip6:2620:109:c00d:104::/64 ip6:2620:109:c006:104::/64 ip6:2620:109:c003:104::/64 ip6:2620:119:50c0:207::/64 ip4:199.101.161.130 mx mx:docusign.net ~all",
      "liveramp-site-verification=yQ2nkwhqszpGRQg_J38S60KHInPVs-dclgyNRtRrlBA",
      "google-site-verification=mMV_EnYaB52OhMo-jbNowf8QVIKcXV3WpXreynLFFEo",
      "448e0dc03e935ecf66d81f1ce3c26b2f2fea13756c031ffc4be91749107f3a79"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com,mailto:yfy3q-9359@rua.dmarc.emailanalyst.com; ruf=mailto:d@ruf.agari.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Sunnyvale, organizationName=Linkedin Corporation, commonName=linkedin.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "May 20 00:00:00 2026 GMT",
    "notAfter": "Nov 20 23:59:59 2026 GMT",
    "san": [
      "linkedin.com"
    ],
    "days_left": 56,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "130.211.32.14",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Checking your browser - reCAPTCHA"
  },
  "mixed_content": [],
  "tech": [
    "Server: ESF"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.linkedin.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 200
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 200,
    "/.git/config": 200,
    "/.env": 200,
    "/.htaccess": 200,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 200,
    "/server-status": 200,
    "/api/": 200
  },
  "subdomains": {
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 20.8,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
