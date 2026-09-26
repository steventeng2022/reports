# Security Audit Report — drift.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://drift.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | drift.com |
| Test date | 2026-09-26 17:43 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=300 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (xaeya4azljd7fj.drift.com and gdn15m85fq4ym1.drift.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=EXb4VABeG7RDBygZaviPE5EEm43o7Law1aGs_JPWr1I; atlassian-domain-verification=cXu9R09NLHAY+K7dTK1SXLMXAx9vcXr4Cpp1VAIbvjJCJ2dZ0g; google-site-verification=43nlxX--h0jQ5cSmfjXsnSnZLCdkw-_tdB1ArWsDmx4
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of drift.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but drift.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

## Evidence (raw response observations)

```json
{
  "domain": "drift.com",
  "dns": {
    "a": [
      "151.101.66.137"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-1960.awsdns-53.co.uk.",
      "ns-1271.awsdns-30.org.",
      "ns-808.awsdns-37.net.",
      "ns-466.awsdns-58.com."
    ],
    "spf": [
      "google-site-verification=EXb4VABeG7RDBygZaviPE5EEm43o7Law1aGs_JPWr1I",
      "atlassian-domain-verification=cXu9R09NLHAY+K7dTK1SXLMXAx9vcXr4Cpp1VAIbvjJCJ2dZ0g4rTWzyhUadykZ0",
      "google-site-verification=43nlxX--h0jQ5cSmfjXsnSnZLCdkw-_tdB1ArWsDmx4",
      "google-site-verification=WBts36f15QIx_SHhtQqJQmPN4udrRODidRIQXPi2FXA",
      "google-site-verification=qb-I0lESyGU3sA7pewDjqWhPLv19DxO6DcpdV5mJzqU",
      "google-site-verification=Oz2hq_0Q1TnZkKGf2y3ju_gVKpIQzAm2-c0gKV_-IHg",
      "google-site-verification=TXlp5hH6h0vO7YBSaqaiHcnvO7t37m2xp5pykbieAIA",
      "v=spf1 ip4:199.15.215.69 include:spf1.drift.com include:spf3.drift.com include:_spf.google.com include:sendgrid.net include:amazonses.com include:spf-0038ba01.pphosted.com -all",
      "google-site-verification=_E3k51OOYCLniiFQOJDxBb7YeUTZsRsnS9obKBOWIBM",
      "apple-domain-verification=D9CdpC9KtRb2SU67",
      "google-site-verification=rTkFvWKmmNOAbgIzQTn8_n-FLHW34IOsl_I02BJwe-o",
      "amazonses:8VA52IIvc5L0tiPo2dTPk95Ix2Fe8fGZ6mOgmlWj1mU=",
      "google-site-verification=FeoHJ-gYBb4Do22PZknzteLMDiNHad1o_4n4_qbtk4Q",
      "atlassian-domain-verification=IK4vQZrJAZuDOM2zNyGYPNXnd4z5wvPTZSUGq0l8uOywrhDgX7D2FjUgj6tttYty",
      "google-site-verification=K-eBDZ2a4JrdklKBnqe2cFaBkEhF1jAJ0i3TjH9Bt3M",
      "zoom-domain-verification = c3bf7571-f003-4704-84be-10ccb4cf6973",
      "jwF+NotcU8L1uVCcbRt9T9TQknJ+J7zcCzTC9Ce1oZI=",
      "asv=d105e8b7dc7943f129ed561be48cb964",
      "bugcrowd-verification=dab931f75202b157a31593fc7c0b5959",
      "google-site-verification=F39d3BrG_GMyTPfgS9BmAOoutEZVSxYNBBeyx1mUnEo",
      "miro-verification=aed7e2c2c984c8243ee35435d2c86c041ddd2d73",
      "status-page-domain-verification=vxfhhw8y9980",
      "docusign=d2419350-d082-40c3-88b7-a362b7dde6d6",
      "google-site-verification=ryKNMbLSr2_ShC67c8PeREDk5u5L-Tqb1Qt3SMZl3bw",
      "google-site-verification=prz0gOLypp4g-rvgvts13UHLmKmQPR-NUmBZ7svLWDA",
      "google-site-verification=cIfqvzYUI06fvgbYARw5UlD9kA9UWn2N9oqCt69ce7Y",
      "google-site-verification=FDRrp3PiBSjA9M9oxffVx1rEVTnoBMk9UbFWLQnhvis",
      "atlassian-domain-verification=eovY2DLWsxOhMcSetCZItREJgqvTapcaJkxT7T3r5NPqZr6BncV5EKM8bpfQYLxL"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:compliance+driftrua@salesloft.com; ruf=mailto:compliance+driftruf@salesloft.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=drift.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR2",
    "notBefore": "Sep  4 07:57:36 2026 GMT",
    "notAfter": "Dec  3 07:57:35 2026 GMT",
    "san": [
      "drift.com"
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
    "ip": "151.101.66.137",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.drift.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.salesloft.com/platform/drift/"
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
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=EXb4VABeG7RDBygZaviPE5EEm43o7Law1aGs_JPWr1I",
    "atlassian-domain-verification=cXu9R09NLHAY+K7dTK1SXLMXAx9vcXr4Cpp1VAIbvjJCJ2dZ0g",
    "google-site-verification=43nlxX--h0jQ5cSmfjXsnSnZLCdkw-_tdB1ArWsDmx4",
    "google-site-verification=WBts36f15QIx_SHhtQqJQmPN4udrRODidRIQXPi2FXA",
    "google-site-verification=qb-I0lESyGU3sA7pewDjqWhPLv19DxO6DcpdV5mJzqU"
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
  "elapsed_s": 18.3,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
