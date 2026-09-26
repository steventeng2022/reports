# Security Audit Report — bandsintown.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bandsintown.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | bandsintown.com |
| Test date | 2026-09-26 17:40 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 4, Info: 11)

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
| 11 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | CT1 | 36 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx/1.25.4; X-Powered-By: Express
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
- **Detail:** Header reveals: nginx/1.25.4
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.bandsintown.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: facebook-domain-verification=szd9g5rep5c2wm6e3yrxk5uqkuygh9; rippling-domain-verification=b5726a43207e41d6; stripe-verification=D1EF7AE8AFB0BBF02CD7A76B56B3BB6CE12B3D6678A1B8A22C2EF8B5621A
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of bandsintown.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but bandsintown.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] 36 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: adops.staging.bandsintown.com, cdn.bandsintown.com, help.pro.bandsintown.com, help.venues.bandsintown.com, oauth.bandsintown.com, publishers.staging.bandsintown.com, status.bandsintown.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "bandsintown.com",
  "dns": {
    "a": [
      "184.193.167.6",
      "3.212.79.149",
      "54.152.243.55"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)"
    ],
    "ns": [
      "ns-417.awsdns-52.com.",
      "ns-1367.awsdns-42.org.",
      "ns-645.awsdns-16.net.",
      "ns-1630.awsdns-11.co.uk."
    ],
    "spf": [
      "facebook-domain-verification=szd9g5rep5c2wm6e3yrxk5uqkuygh9",
      "rippling-domain-verification=b5726a43207e41d6",
      "MS=ms12811150",
      "stripe-verification=D1EF7AE8AFB0BBF02CD7A76B56B3BB6CE12B3D6678A1B8A22C2EF8B5621AD9CB",
      "asv=aeeef7fc6b18aca440b92141741bdb9f",
      "mandrill_verify.dMoB27k4ZLW5-FAhb5RTgg",
      "google-site-verification=f1CWKwhuZPLcgwoyE41lip_z1dZCy2xnA-Q7evMzrSU",
      "9fldg144ers8mh6f24ffrc3thk",
      "v=spf1 a mx include:sendgrid.net include:_spf.google.com include:spf.protection.outlook.com include:stspg-customer.com -all",
      "dailymotion-domain-verification=dm21h9ylyllu1p69n",
      "perplexity-ai-domain-verification-376w2f=2PeL8yNlYAkys7oM52uT6wTdC",
      "mlkfx9phjb4y6h395lt8lsy5b4sjkgc4",
      "hmkuhqbttdq4i998kareathvto",
      "status-page-domain-verification=qn6chxt05qrd",
      "rippling-domain-verification=e5824847937fee1e",
      "atlassian-domain-verification=n3FcpfaRP0Kv679ha0/mirPFGK3ftRdN7l97Ca2T9Zz1uaL3wysi2f4VO536tNMm",
      "anthropic-domain-verification-tww6x4=SWB50zFKsYjXe3H2zayd8Sz1t"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; rua=mailto:de1f17b4@mxtoolbox.dmarc-report.com,mailto:dmarc@bandsintown.com; ruf=mailto:de1f17b4@forensics.dmarc-report.com,mailto:dmarc@bandsintown.com; adkim=r; fo=1; pct=100; ri=86400"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=*.fan-website-preprod.prod.bandsintown.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "May 16 00:00:00 2026 GMT",
    "notAfter": "Nov 29 23:59:59 2026 GMT",
    "san": [
      "*.fan-website-preprod.prod.bandsintown.com",
      "bandsintown.com",
      "*.bandsintown.com",
      "*.prod.bandsintown.com"
    ],
    "days_left": 64,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "184.193.167.6",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx/1.25.4",
    "X-Powered-By: Express"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.bandsintown.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://bandsintown.com/"
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
    "source": "certspotter",
    "count": 36,
    "notable": [
      "adops.staging.bandsintown.com",
      "cdn.bandsintown.com",
      "help.pro.bandsintown.com",
      "help.venues.bandsintown.com",
      "oauth.bandsintown.com",
      "publishers.staging.bandsintown.com",
      "status.bandsintown.com"
    ],
    "sample": [
      "ablink.hello.bandsintown.com",
      "adops.bandsintown.com",
      "adops.staging.bandsintown.com",
      "artist.bandsintown.com",
      "artistfeedback.bandsintown.com",
      "bandsintown.com",
      "bitdatahub.bandsintown.com",
      "business.bandsintown.com",
      "cdn.bandsintown.com",
      "company.bandsintown.com",
      "corp.bandsintown.com",
      "datahub.bandsintown.com",
      "email-preview.bandsintown.com",
      "fanapi.bandsintown.com",
      "help.pro.bandsintown.com",
      "help.venues.bandsintown.com",
      "manager-storybook.prod.bandsintown.com",
      "manager-storybook.stg.bandsintown.com",
      "managers.bandsintown.com",
      "oauth.bandsintown.com"
    ]
  },
  "apex_txt": [
    "facebook-domain-verification=szd9g5rep5c2wm6e3yrxk5uqkuygh9",
    "rippling-domain-verification=b5726a43207e41d6",
    "stripe-verification=D1EF7AE8AFB0BBF02CD7A76B56B3BB6CE12B3D6678A1B8A22C2EF8B5621A",
    "google-site-verification=f1CWKwhuZPLcgwoyE41lip_z1dZCy2xnA-Q7evMzrSU",
    "dailymotion-domain-verification=dm21h9ylyllu1p69n"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null
    }
  },
  "elapsed_s": 33.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
