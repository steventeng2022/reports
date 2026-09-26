# Security Audit Report — greenpeace.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://greenpeace.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | greenpeace.org |
| Test date | 2026-09-26 17:46 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 5, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 10 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 11 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 12 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 13 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 10. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.greenpeace.org/.well-known/mta-sts/policy.txt -> 530
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 11. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: hubspot-domain-verification=M2MzZmRkZGEtYWE2OS00ZWQyLTg2ZDQtODkwZWM3NWM1MDY4; hubspot-domain-verification=MzUyNzQwMTUtOWM0Yi00ODAzLThjNDMtYTgyZmIxMGQ1MzYy; hubspot-domain-verification=ZjlkY2RjMTYtNjQxMy00NWY1LWE2NjAtNGQ4MzNhNDMxYTMx
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 12. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of greenpeace.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 13. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but greenpeace.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

## Evidence (raw response observations)

```json
{
  "domain": "greenpeace.org",
  "dns": {
    "a": [
      "35.184.130.59"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "aspmx3.googlemail.com (pref 10)"
    ],
    "ns": [
      "dns200.anycast.me.",
      "ns200.anycast.me."
    ],
    "spf": [
      "hubspot-domain-verification=M2MzZmRkZGEtYWE2OS00ZWQyLTg2ZDQtODkwZWM3NWM1MDY4",
      "hubspot-domain-verification=MzUyNzQwMTUtOWM0Yi00ODAzLThjNDMtYTgyZmIxMGQ1MzYy",
      "hubspot-domain-verification=ZjlkY2RjMTYtNjQxMy00NWY1LWE2NjAtNGQ4MzNhNDMxYTMx",
      "hubspot-domain-verification=NDBjZjYxZDAtY2RiYS00NTMwLWJmYzMtZDNhNWY5NjYwZmY4",
      "hubspot-domain-verification=OTNlMzAyZGEtZTIxOC00YmI5LThjZGItMzgwMzJhN2FkZTAz",
      "hubspot-domain-verification=NDkwZTAyNjctYjBmZS00MzYwLThiY2QtMGExZDYxYjQ2MTMz",
      "hubspot-domain-verification=MGQ0MzhmNDEtZmJiMC00MzkzLWI3NzktZjVhNTY2M2Q0MjZi",
      "hubspot-domain-verification=YzRjMzc2Y2UtN2U2Yi00ZjYwLWI4NzItYzQ4ZGQ3NmE1ZGY3",
      "langdock-verify=16mjZC5NFZba6udsMuM_svXXjMnz7TJZwChc5A_daWs",
      "atlassian-domain-verification=HbwL1jmfLZJuo8K6HDVKoCkZSfgraX61OKTyE5SsvfK44k4qKWNBSWijsnAScInm",
      "a1379742935a9b4fe5220281db19c39a111b927ac4e7b6dd9772463d7f2ad5a1",
      "hubspot-domain-verification=OTY4NDFiN2ItN2VjZi00MGExLThlZDQtZDkzMmQyNjlkOTI0",
      "hubspot-domain-verification=ZGY3NTFmZDYtYWU3Yi00MWY5LWIxNzUtZTMyY2MyNGE0N2E1",
      "v=spf1 ip4:103.151.192.0/23 ip4:108.179.144.0/20 ip4:134.128.64.0/18 ip4:139.162.181.157 ip4:139.180.17.0/24 ip4:141.193.184.128/25 ip4:141.193.184.32/27 ip4:141.193.184.64/26 ip4:141.193.185.128/25 ip4:141.193.185.32/27 ip4:141.193.185.64/26",
      " ip4:141.94.7.160/28 ip4:141.94.7.30 ip4:141.94.7.31 ip4:141.94.7.32/27 ip4:143.244.80.0/20 ip4:148.105.0.0/16 ip4:149.72.0.0/16 ip4:158.247.16.0/20 ip4:159.183.0.0/16 ip4:159.26.176.0/20 ip4:167.89.0.0/17 ip4:168.245.0.0/17 ip4:172.104.151.106",
      " ip4:172.104.151.138 ip4:18.208.124.128/25 ip4:185.12.80.0/22 ip4:185.189.236.0/22 ip4:185.211.120.0/22 ip4:185.250.236.0/22 ip4:185.46.182.1 ip4:185.46.182.200/29 ip4:185.46.182.208/31 ip4:188.172.128.0/20 ip4:192.161.144.0/20 ip4:192.254.112.0/20",
      " ip4:195.154.97.49 ip4:198.2.128.0/18 ip4:198.21.0.0/21 ip4:198.37.144.0/20 ip4:199.127.232.0/22 ip4:199.255.192.0/22 ip4:205.201.128.0/20 ip4:206.55.144.0/20 ip4:208.117.48.0/20 ip4:209.85.128.0/17 ip4:212.232.31.106 ip4:216.139.64.0/19",
      " ip4:216.198.0.0/18 ip4:216.221.160.0/19 ip4:223.165.113.0/24 ip4:223.165.115.0/24 ip4:223.165.118.0/23 ip4:223.165.120.0/23 ip4:23.249.208.0/20 ip4:23.251.224.0/19 ip4:24.110.64.0/18 ip4:3.210.190.0/24 ip4:3.93.157.0/24 ip4:34.121.139.65",
      " ip4:34.173.35.64 ip4:34.223.183.171 ip4:35.224.129.142 ip4:45.14.148.0/22 ip4:50.31.32.0/19 ip4:51.15.7.188 ip4:52.204.149.140 ip4:52.39.127.104 ip4:52.40.203.205 ip4:52.89.177.132 ip4:54.174.52.0/24 ip4:54.174.57.0/24 ip4:54.174.59.0/24",
      " ip4:54.174.60.0/23 ip4:54.174.63.0/24 ip4:54.185.198.195 ip4:54.185.51.55 ip4:54.187.103.206 ip4:54.200.182.110 ip4:54.200.5.133 ip4:54.213.101.86 ip4:54.213.101.90 ip4:54.214.75.131 ip4:54.218.238.220 ip4:54.240.0.0/18 ip4:54.240.64.0/18",
      " ip4:66.187.204.0/23 ip4:69.169.224.0/20 ip4:74.125.0.0/16 ip4:76.223.128.0/19 ip4:76.223.176.0/20 ip4:77.74.54.216/32 ip4:77.74.54.242 ip4:77.74.54.75 ip4:87.253.232.0/21 ip4:88.191.140.49 ip4:88.191.149.244 ip4:91.204.117.0/26 ip4:91.204.117.10",
      " ip4:91.204.117.11 ip4:91.204.117.12 ip4:91.204.117.13 ip4:91.204.117.4 ip4:91.204.117.80/28 ip4:98.77.0.0/16 ip6:2001:4860:4864::/56 ip6:2404:6800:4864::/56 ip6:2607:f8b0:4864::/56 ip6:2800:3f0:4864::/56 ip6:2a00:1450:4864::/56",
      " ip6:2a01:310:8312:1035::75:0 ip6:2c0f:fb50:4864::/56 exists:%{i}._spf.mta.salesforce.com -all",
      "hubspot-domain-verification=ZGY3Nzk4MWItMGFhMS00ZjExLTlhODgtZjgyNDMyMjA4ZWZm",
      "atlassian-domain-verification=5V9f1pwvULZYq1iMya6QtJWUwPi3jfiRXPrshFO5owbQi8Nhj4J4bk4R8gzG5Fvi",
      "hubspot-domain-verification=MjgwOTA5MjctYTVjMi00OWM5LWI0YTMtMzFlNWNjMTc1Njg3",
      "anthropic-domain-verification-d2gnan=P2eHpvCqnCaszHVvpeSbguOuA",
      "atlassian-domain-verification=KByIuBBRnIkRV94u5cBWdoNJayjIyC1hoMA5JdtgzsGCVlF79OYxZa93smtaVu8B",
      "google-site-verification=cabk3280FRUiQMgdVbPPPTdbytCnXe1LFEpYWIW5TMY",
      "hubspot-domain-verification=NzYzYWIyYTUtZDMzNy00MWIzLTk5ZDEtZWM3OTEzNTNjZjZi",
      "hubspot-domain-verification=M2U3OTFmYWYtNTZmZS00MGMxLWI2YjgtYmU0M2IyMzRhN2Rj",
      "hubspot-domain-verification=ZGMwMjZlM2ItNTE5YS00OGNiLWEyYmEtYjJhOTZjZjVkOTA5",
      "mixpanel-domain-verify=2e95c43d-2182-4022-842b-483081b3d9f9",
      "hubspot-domain-verification=NmM5ZmZlMTMtOWE1NS00ZWE2LWI2OTMtZGI0NGNlN2U5ZWI1",
      "amazonses:U0TjwasGtQ7BX+vOwNfZMqOvXCTkrDvAMeoQ2vAkDsE=",
      "stripe-verification=301f6dc48b524378870b3f10b245b8233f95a3b71318492c17d046d3dd8da6a5",
      "hubspot-domain-verification=ODVhNTkyNGQtOTljYy00ZWE4LTljNjItNjFiMDExNTYxNGEx",
      "atlassian-sending-domain-verification=8d3a2412-a678-4ddb-87b5-855d492868ba"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; aspf=r; adkim=r; pct=100; rua=mailto:infra-mail-reports-group@greenpeace.org,mailto:fb08c529499e4c218be6a8b94c687513@dmarc-reports.cloudflare.net; fo=1:d:s"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=greenpeace.org",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR2",
    "notBefore": "Sep  4 02:43:17 2026 GMT",
    "notAfter": "Dec  3 02:43:16 2026 GMT",
    "san": [
      "greenpeace.org"
    ],
    "days_left": 67,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "35.184.130.59",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.greenpeace.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.greenpeace.org/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "hubspot-domain-verification=M2MzZmRkZGEtYWE2OS00ZWQyLTg2ZDQtODkwZWM3NWM1MDY4",
    "hubspot-domain-verification=MzUyNzQwMTUtOWM0Yi00ODAzLThjNDMtYTgyZmIxMGQ1MzYy",
    "hubspot-domain-verification=ZjlkY2RjMTYtNjQxMy00NWY1LWE2NjAtNGQ4MzNhNDMxYTMx",
    "hubspot-domain-verification=NDBjZjYxZDAtY2RiYS00NTMwLWJmYzMtZDNhNWY5NjYwZmY4",
    "hubspot-domain-verification=OTNlMzAyZGEtZTIxOC00YmI5LThjZGItMzgwMzJhN2FkZTAz"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null
    }
  },
  "elapsed_s": 22.0,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
