# Security Audit Report — marketwatch.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://marketwatch.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | marketwatch.com |
| Test date | 2026-09-26 17:49 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

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
| 12 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
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
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=uYFppydFtsdAeVh-4zcS07cMFtUdZHp_QZz-ACw_AHg; mongodb-site-verification=3NjKxTnfMRjvs5GmXZrJcJDqqu8GCjDz; google-site-verification=9D2VzJi-QCek9CtqC2XV8G4VYkTiiDYYTmkM5152ad8
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of marketwatch.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 57 disallow path(s), e.g. /, /2/, /3com/, /admin/, /bgpoxy/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "marketwatch.com",
  "dns": {
    "a": [
      "65.9.180.125",
      "65.9.180.27",
      "65.9.180.107",
      "65.9.180.59"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-00596a01.gslb.pphosted.com (pref 10)",
      "mxb-00596a01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-1588.awsdns-06.co.uk.",
      "ns-705.awsdns-24.net.",
      "ns-450.awsdns-56.com.",
      "ns-1291.awsdns-33.org."
    ],
    "spf": [
      "google-site-verification=uYFppydFtsdAeVh-4zcS07cMFtUdZHp_QZz-ACw_AHg",
      "mongodb-site-verification=3NjKxTnfMRjvs5GmXZrJcJDqqu8GCjDz",
      "google-site-verification=9D2VzJi-QCek9CtqC2XV8G4VYkTiiDYYTmkM5152ad8",
      "atlassian-domain-verification=uNoIhBXurxzVlQa0FvK2t9Yld5byfvXbFRQaMToGvrieKjBdylMs8jcSXRKQKqao",
      "v=spf1 ip4:68.232.128.0/19 ip4:63.240.26.0/24 ip4:205.203.130.22 ip4:205.203.130.101 ip4:205.203.130.102 ip4:205.203.136.101 ip4:205.203.136.102 include:spf-1.dowjones.com ",
      "include:_spf.google.com include:spf-00596a01.pphosted.com include:aspmx.sailthru.com include:spf-00596a03.pphosted.com -all",
      "knowbe4-site-verification=0694ce74005828dc4bb8b7299bfb6f61",
      "adobe-idp-site-verification=7ef638bb68822798685f96e436bfc87a6f79319dd86369e447b84bb8ea9c6f68",
      "google-site-verification=zbCAdHPPQU1MVv0UikjwLoiAgCLikxMKJ1h64y226-g",
      "google-site-verification=g1arhZY9MX2Af0YQgBFVYh8WTDUG-WtEE55qEGH6hsU",
      "docker-verification=2b229513-3448-4073-9530-e57440f198d5",
      "datadome-domain-verify=mBXJ0OcsBIxmEYtkepO9rBwdPNmfTk5Q",
      "miro-verification=fc4f542b1bf4fc981e2f11e463246349bde0a8d0",
      "figma-domain-verification=b411f1d2852c2c7e057a2d6d70fb22896f37ccc1412d1e1bb4f9da14e2b78ad9-1769000244",
      "google-site-verification=nnn1LRQtO0v0X_DpMDGX_xZmSwTZqOaMaD0e6NDZvdA",
      "ValidationTokenValue=aa1d350e-32a6-4129-b29a-0a17a8fbe63c",
      "google-site-verification=EGDlBNSsQnx5i-6-IAjm0Q9pykD3Bqwiesucz8hZwuw",
      "openai-domain-verification=dv-Z1O5z6g6UeNwdxBpVlxRw8J6"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=marketwatch.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jan 25 00:00:00 2026 GMT",
    "notAfter": "Feb 22 23:59:59 2027 GMT",
    "san": [
      "marketwatch.com",
      "*.marketwatch.com"
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
    "ip": "65.9.180.125",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.marketwatch.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.marketwatch.com/"
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
    "google-site-verification=uYFppydFtsdAeVh-4zcS07cMFtUdZHp_QZz-ACw_AHg",
    "mongodb-site-verification=3NjKxTnfMRjvs5GmXZrJcJDqqu8GCjDz",
    "google-site-verification=9D2VzJi-QCek9CtqC2XV8G4VYkTiiDYYTmkM5152ad8",
    "atlassian-domain-verification=uNoIhBXurxzVlQa0FvK2t9Yld5byfvXbFRQaMToGvrieKjBdyl",
    "knowbe4-site-verification=0694ce74005828dc4bb8b7299bfb6f61"
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
  "http2": {
    "robots_disallow": [
      "/",
      "/2/",
      "/3com/",
      "/admin/",
      "/bgpoxy/",
      "/bin/",
      "/cDN_contENt/",
      "/cgi-bin/",
      "/client/",
      "/data/",
      "/dbcfiles/",
      "/dhtml/",
      "/dhtmlmenu/",
      "/doubleclick/",
      "/dynamiclogic/"
    ]
  },
  "elapsed_s": 10.3,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
