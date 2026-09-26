# Security Audit Report — pandora.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pandora.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | pandora.com |
| Test date | 2026-09-26 14:55 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 4, Info: 8)

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
| 11 | info | CT1 | 45 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 12 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache
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
- **Detail:** Header reveals: Apache
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] 45 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: blog.pandora.com, help.pandora.com, www.help.pandora.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 12. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: www.help.pandora.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "pandora.com",
  "dns": {
    "a": [
      "199.116.164.229"
    ],
    "aaaa": [
      "2620:106:e001:f00d::e7"
    ],
    "cname": null,
    "mx": [
      "mx0a-0051e301.pphosted.com (pref 3)",
      "mx0b-0051e301.pphosted.com (pref 3)"
    ],
    "ns": [
      "dns2.p05.nsone.net.",
      "ns2.pandora.com.",
      "ns4.pandora.com.",
      "dns1.p05.nsone.net."
    ],
    "spf": [
      "monday-com-verification=Y7tba9sDRtLGwJrmA-A2bxVKMIOuhp5g9YnzcMJifOo",
      "/4SPMALLPHvERsW46Wt5HeyzV7tWXyqSCVio3D+e46JOIQ1Lx4ayzLacYa2Nani5VZLIsG6QzSbAxqQorgT8Pw==",
      "openai-domain-verification=dv-MtwM2KzO6fmabwatU3A5suMJ",
      "stripe-verification=b7edf88636d477ae4501df1dbebcda1b9f3eb5f895d94a5dcaa35715fd8525a7",
      "google-site-verification=7rxKTJwaOBuE3vNSi4Yl0fG04rCK2xr4rYvsy2yMPgs",
      "drift-domain-verification=7dcb7704b70c0f98d5f1188a55e7fe4c1a0d0a5c8474f0b5d7feaf2a17ddaf8b",
      "_9ax3ucie5r4ihbdbsi4tuuy6jex2x7y",
      "atlassian-domain-verification=suALAhcWjB6Eq0SuX424kLGZ8kMs8yfsj4LDWz6QHyorTk7BzUFfbXXgI4pyznZy",
      "liveramp-site-verification=3auN45Pf2H9Obu6SoSX-izAUSRjBnVPQbEnXgyJK8MQ",
      "stripe-verification=46db797e734d25037c8a1966048d4d0a26f34600f23375c9ab8f1b327dc5b023",
      "apple-domain-verification=GVC0xaZwt2Sv9Ivm",
      "stripe-verification=47c5a8c489eea6dc578dfd12d08d3b7accf87c7729c8958144a35f50361cc92a",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
      "facebook-domain-verification=nn42grx580r7pjlyzjzxv3mrnn5lpx",
      "MS=ms48003601",
      "stripe-verification=7700e585bc13984d32505fc0743dd1742a7b00ab8f89fd43edbb64b7e86eb3df",
      "stripe-verification=eef61a09f3c1c4f6890acce9bff70c102c0c389cc77e9970a3b2a17e582f3b27",
      "onetrust-domain-verification=52ed295d1cc747c8b4a923ee0d52bb89",
      "jetbrains-domain-verification=1erv1ckkr599h7o8n4nnatntx",
      "stripe-verification=9afcd9b96859582b2edf39640758f0a7ca9bbbc04fc0acd4eda69d964978923b",
      "make-domain-verification=0d44a7b3-d8f7-4bc0-bf24-53609a1f2fe7",
      "webexdomainverification.4C675B8AC948B136E053AB06FC0A3F65=c8670c99-cf44-4da5-a347-0e378903bd08",
      "shopify-verification-code=QZZP4RdLtXmhnyVfqGJxOtDrTJwdHv",
      "google-site-verification=ZmhaVAHHT8AaKg7hP9Mmd3mrk8AMaSh90uPg77P-Gyo",
      "anthropic-domain-verification-cehw0s=Q6GJ2C5R4orf8oDA6ntjc8jiI",
      "docker-verification=09663cec-b2f4-4ce1-92a8-9bdc828efd88",
      "stripe-verification=6151a13c2e26e26166de3da9cbc43b4b418109e806e0fef941a34da28edc06ca",
      "airtable-verification=92001d7da07339e0b17a973f2faaa71b",
      "Pandora",
      "bugcrowd-verification=9224a322abc2e3e36bf6aef0cf1d2977",
      "stripe-verification=a2efa4b173f85f9b16a2fe262a5d7fa95a0b18f0ba884723050e917033a5af28",
      "zapier-domain-verification-challenge=0c6f32b8-f62f-4918-aa85-11e2476e37ec",
      "stripe-verification=eb9cdfa80af377c6421610f8153fd4151acb46fe9414e78a4ce90c2d0d82f93a",
      "stripe-verification=9ac87819ed1e8c4c43fb4806e46ee7ac5135b3ac5eb80fc1ceca8ec0bf1fd7c0"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Oakland, organizationName=Pandora Media LLC, commonName=*.pandora.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=Thawte TLS RSA CA G1",
    "notBefore": "Sep 15 00:00:00 2026 GMT",
    "notAfter": "Apr  1 23:59:59 2027 GMT",
    "san": [
      "*.pandora.com",
      "pandora.com"
    ],
    "days_left": 187,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "199.116.164.229",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
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
      "origin": "https://sub.pandora.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.pandora.com"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 301",
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
    "source": "certspotter",
    "count": 45,
    "notable": [
      "blog.pandora.com",
      "help.pandora.com",
      "www.help.pandora.com"
    ],
    "sample": [
      "ac.pandora.com",
      "ads.pandora.com",
      "advertising.pandora.com",
      "blog.pandora.com",
      "brandadvertising-sandbox.pandora.com",
      "brandadvertising.pandora.com",
      "brands.pandora.com",
      "bread2.pandora.com",
      "ce.pandora.com",
      "community.pandora.com",
      "dam.pandora.com",
      "delivery.pandora.com",
      "design.pandora.com",
      "device-tuner.pandora.com",
      "engineering.pandora.com",
      "esb-dev-int.pandora.com",
      "esb-dev.pandora.com",
      "esb-int.pandora.com",
      "esb.pandora.com",
      "google-receiver.cs.pandora.com"
    ],
    "dangling": [
      "www.help.pandora.com"
    ]
  },
  "elapsed_s": 24.8,
  "rechecked": "2026-09-26 16:29 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
