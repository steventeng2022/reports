# Security Audit Report — business.linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://business.linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | business.linkedin.com |
| Test date | 2026-09-26 14:53 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 0, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | CT1 | 2 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.41.41:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.41.41:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] 2 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "business.linkedin.com",
  "dns": {
    "a": [
      "104.18.41.41",
      "172.64.146.215"
    ],
    "aaaa": [
      "2a06:98c1:310b::ac40:92d7",
      "2a06:98c1:3109::6812:2929"
    ],
    "cname": "microsites-cn.linkedin.com.",
    "mx": [],
    "ns": [],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Sunnyvale, organizationName=Linkedin Corporation, commonName=afd.microsites.linkedin.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Aug 22 00:00:00 2026 GMT",
    "notAfter": "Feb 22 23:59:59 2027 GMT",
    "san": [
      "afd.microsites.linkedin.com",
      "engineering.linkedin.com",
      "addtoprofile.linkedin.com",
      "lifg.linkedin.com",
      "rum15.perf.linkedin.com",
      "about.linkedin.com",
      "blog.linkedin.com",
      "brand.linkedin.com",
      "bringinyourparents.linkedin.com",
      "business.linkedin.com",
      "careers.linkedin.com",
      "cba.linkedin.com",
      "certification.linkedin.com",
      "cities.linkedin.com",
      "cms.linkedin.com",
      "commsconnect.linkedin.com",
      "conscious.linkedin.com",
      "contacts.linkedin.com",
      "customersuccess.linkedin.com",
      "data.linkedin.com",
      "design.linkedin.com",
      "developer.linkedin.com",
      "economicgraph.linkedin.com",
      "economicgraphchallenge.linkedin.com",
      "emea.marketing.linkedin.com",
      "financeconnect.linkedin.com",
      "gsk.linkedin.com",
      "hackday.linkedin.com",
      "imagine.linkedin.com",
      "itlist.linkedin.com",
      "jp.learn.linkedin.com",
      "jp.navi.linkedin.com",
      "learn.linkedin.com",
      "learning.linkedin.com",
      "legal.linkedin.com",
      "linkedinforgood.linkedin.com",
      "lists.linkedin.com",
      "live.linkedin.com",
      "manchester.linkedin.com",
      "members.linkedin.com",
      "mentor.linkedin.com",
      "mobile.linkedin.com",
      "news.linkedin.com",
      "nonprofit.linkedin.com",
      "opportunity.linkedin.com",
      "ourstory.linkedin.com",
      "partner.linkedin.com",
      "premium.linkedin.com",
      "press.linkedin.com",
      "privacy.linkedin.com",
      "projectinployment.linkedin.com",
      "purchasing.linkedin.com",
      "safety.linkedin.com",
      "sales.linkedin.com",
      "salesconnect.linkedin.com",
      "security.linkedin.com",
      "smallbusiness.linkedin.com",
      "socialimpact.linkedin.com",
      "speakers.linkedin.com",
      "stories.linkedin.com",
      "studentcareers.linkedin.com",
      "students.linkedin.com",
      "suppliers.linkedin.com",
      "talent.linkedin.com",
      "talentconnect.linkedin.com",
      "tomorrow.linkedin.com",
      "ued.linkedin.com",
      "university.linkedin.com",
      "veterans.linkedin.com",
      "volunteer.linkedin.com",
      "insiders.linkedin.com",
      "biyp.linkedin.com",
      "nonprofits.linkedin.com",
      "newsle.com",
      "www.brand.linkedin.com",
      "www.business.linkedin.com",
      "www.customersuccess.linkedin.com",
      "www.engineering.linkedin.com",
      "www.learning.linkedin.com",
      "www.legal.linkedin.com",
      "www.mobile.linkedin.com",
      "www.nonprofits.linkedin.com",
      "www.opportunity.linkedin.com",
      "www.premium.linkedin.com",
      "www.security.linkedin.com",
      "www.speakers.linkedin.com",
      "www.developer.linkedin.com"
    ],
    "days_left": 149,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.41.41",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html;charset=utf-8",
    "title": "Business Solutions on LinkedIn I LinkedIn"
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": ".linkedin.com",
      "samesite": "none"
    },
    {
      "domain": "linkedin.com",
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
      "origin": "https://sub.business.linkedin.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 200
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 400",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 2,
    "notable": [],
    "sample": [
      "business.linkedin.com",
      "www.business.linkedin.com"
    ]
  },
  "elapsed_s": 8.6,
  "rechecked": "2026-09-26 14:53 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
