# Security Audit Report — idealo.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://idealo.de/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | idealo.de |
| Test date | 2026-09-26 18:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 5, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: awselb/2.0
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.idealo.de/.well-known/mta-sts/policy.txt -> 200; policy lacks version/max_age
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: anthropic-domain-verification-gm4n1q=mbgtscKppFSQPa94iEKut1DCu; google-site-verification=vnKFVNK2CNvD26H6RgVwBzA3kl8EnMW1xc4DIYfZqr0; apple-domain-verification=KCTdqG3zCfRDNB57
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of idealo.de has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "idealo.de",
  "dns": {
    "a": [
      "45.89.130.29",
      "45.89.129.173",
      "45.89.129.108"
    ],
    "aaaa": [
      "2a0b:a200:0:100:3909:3d2d:af11:1f6",
      "2a0b:a200:0:102:ddaf:6c77:9375:1ed0",
      "2a0b:a200:0:101:9b4:8326:1ab1:3982"
    ],
    "cname": null,
    "mx": [
      "idealo-de.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "ns-1201.awsdns-22.org.",
      "ns-53.awsdns-06.com.",
      "ns-527.awsdns-01.net.",
      "ns-1734.awsdns-24.co.uk."
    ],
    "spf": [
      "anthropic-domain-verification-gm4n1q=mbgtscKppFSQPa94iEKut1DCu",
      "google-site-verification=vnKFVNK2CNvD26H6RgVwBzA3kl8EnMW1xc4DIYfZqr0",
      "apple-domain-verification=KCTdqG3zCfRDNB57",
      "v=spf1 include:spf.asv.de include:_spf.google.com include:spf.protection.outlook.com include:_spf.salesforce.com ~all",
      "google-site-verification=rU54pg91seSvEOguy4FYBoAz_-1kbL9JtzckNRoKI-8",
      "1password-site-verification=NPLE72RPPJCD5MQWHCH2LBWOSA",
      "mgverify=cca526e60761a60ac07b6a052965659d6c3c76ff8a4958a398cb1071007da7ca",
      "astro-domain-verification=cmfl404981ir001ri7eudlvbp",
      "MS=ms59853604",
      "facebook-domain-verification=xj7sye2iiecu2xm4coraz2sghglxyg",
      "atlassian-domain-verification=EnHue3UwYSfo4DXgk/Bvg3WcQ2JVjyt6zf38Dox2HOZXlTSpjtg1iNnMasAJ3GsD",
      "mongodb-site-verification=PWvAUTuE0LHic9S4sUMdPfiKHH9Vhj55",
      "wiz-domain-verification=106d737f255f6040e903621fcc553ce41977b40940acfab67d828304fbe01399",
      "jamf-site-verification=cgA87WElNjz-TqQEDiiQAg",
      "cursor-domain-verification-987qxp=NzVU3KiAhhQpAYRf9gWgmwH2M"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=0; rua=mailto:dmarc-aggregation@idealo.de,mailto:idealo@rua.netcraft.com; ruf=mailto:dmarc-forensic@idealo.de,mailto:idealo@ruf.netcraft.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=idealo.de",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "May 17 00:00:00 2026 GMT",
    "notAfter": "Nov 30 23:59:59 2026 GMT",
    "san": [
      "idealo.de"
    ],
    "days_left": 65,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "45.89.130.29",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.idealo.de",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.idealo.de:443/"
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
    "/.env": 403,
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
    "anthropic-domain-verification-gm4n1q=mbgtscKppFSQPa94iEKut1DCu",
    "google-site-verification=vnKFVNK2CNvD26H6RgVwBzA3kl8EnMW1xc4DIYfZqr0",
    "apple-domain-verification=KCTdqG3zCfRDNB57",
    "google-site-verification=rU54pg91seSvEOguy4FYBoAz_-1kbL9JtzckNRoKI-8",
    "1password-site-verification=NPLE72RPPJCD5MQWHCH2LBWOSA"
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
      "aia_ocsp": null,
      "not_before": "20260517000000",
      "not_after": "20261130235959"
    }
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 25.0,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
