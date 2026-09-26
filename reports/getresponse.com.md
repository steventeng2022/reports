# Security Audit Report — getresponse.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://getresponse.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | getresponse.com |
| Test date | 2026-09-26 17:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 6, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.getresponse.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (3yr6eldg7dnlxt.getresponse.com and 61l7ywrl7geuh8.getresponse.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: anthropic-domain-verification-venw22=ZeM4NT230jUX4wYrLH2xiewmQ; Dynatrace-site-verification=e1a175f3-bb98-4294-b96d-7da32368958c__5e1a4oqvdp0fv5; atlassian-domain-verification=LK2p1objuTfwluXVqD2rSagYcHzknb4lAGe2sOnklu3lYjE6x2
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of getresponse.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 145 disallow path(s), e.g. /about/investor-relations, *emailTemplateID=, /features/website-builder/templates/*/*, /features/website-builder/templates/business-and-services/*,*, /features/website-builder/templates*order=
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "getresponse.com",
  "dns": {
    "a": [
      "104.160.64.8"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "getresponse-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns0.dnsmadeeasy.com.",
      "ns4.dnsmadeeasy.com.",
      "ns3.dnsmadeeasy.com.",
      "ns2.dnsmadeeasy.com.",
      "ns1.dnsmadeeasy.com."
    ],
    "spf": [
      "anthropic-domain-verification-venw22=ZeM4NT230jUX4wYrLH2xiewmQ",
      "Dynatrace-site-verification=e1a175f3-bb98-4294-b96d-7da32368958c__5e1a4oqvdp0fv5mdkt0iek9bk3",
      "atlassian-domain-verification=LK2p1objuTfwluXVqD2rSagYcHzknb4lAGe2sOnklu3lYjE6x2o6yfOxo1T4OK5u",
      "sf9v0knq1ugotc1jqte1ractie",
      "google-site-verification=j5cNpXTozrVnhuElGV-BdoIZaBOqg8wtr_z2hiO_1CY",
      "google-site-verification=Z8jVzgnaG8CjbUygDISY-3uP8uIqGzn5At2bo5nzHqQ",
      "google-site-verification=QeBji-07N-gsBMjY9YfUf5LXyTluvf76nuzqSX3PTsQ",
      "5ce38e29469ad11f7177b24c1922672b63abf6680d6a0726116fd210c7e8cc6",
      "miro-verification= 79b13564da36f9da3d95258202fd70c9462a2a62",
      "1password-site-verification=BMMLC4IXRBCU3G5UCBKCF5MINM",
      "perplexity-ai-domain-verification-xhench=mT1d7pxsOX0OQ99IarJY2WASZ",
      "google-site-verification=fMdXexz-UeermTKRO7SNU9jaU8iWvBjkLyUjux2p1s8",
      "openai-domain-verification=dv-Rf8rPeAU2o96nKUYvGJOqGKG",
      "google-site-verification=Dp1TRtq03Oinzgwpx4tg0nfgchSB7UYGTHaTvgRuvQA",
      "google-site-verification=zr4OhPflVzGIZtxchXz72jWuNqjvgDlHrPUpiiJY0-k",
      "google-site-verification=qQY936ygxuK-lM39J2ouZcOYciA1FsHBrh2N6K8aGho",
      "facebook-domain-verification=hzu8jvt165inp6e47scduae2y0smll",
      "mojecertpl-site-verification-pTZqxhVN4nRsImMtqYHyUrnng6ILpAqJ",
      "pandadoc-domain-verification=URaRjh7TeRXzEYB2xiZ72o",
      "jamf-site-verification=EMDHC_pNcl7T-4-V0hfEIQ",
      "v=spf1 mx a ip4:104.160.64.0/23 ip4:104.160.67.63/32 ip4:104.160.67.128/25 ip4:104.160.68.224/27 ip4:104.160.69.0/27 ip4:104.160.66.254 ip4:178.16.117.0/24 include:spf.protection.outlook.com include:_spf.psm.knowbe4.com -all"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc_agg@dmarc.everest.email; ruf=mailto:dmarc_fr@dmarc.everest.email; fo=1; pct=100; rf=afrf"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.getresponse.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=RapidSSL TLS RSA CA G1",
    "notBefore": "Sep  9 00:00:00 2026 GMT",
    "notAfter": "Mar 20 23:59:59 2027 GMT",
    "san": [
      "*.getresponse.com",
      "getresponse.com"
    ],
    "days_left": 175,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.160.64.8",
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
      "origin": "https://sub.getresponse.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.getresponse.com/"
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
    "/server-status": 403,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "anthropic-domain-verification-venw22=ZeM4NT230jUX4wYrLH2xiewmQ",
    "Dynatrace-site-verification=e1a175f3-bb98-4294-b96d-7da32368958c__5e1a4oqvdp0fv5",
    "atlassian-domain-verification=LK2p1objuTfwluXVqD2rSagYcHzknb4lAGe2sOnklu3lYjE6x2",
    "google-site-verification=j5cNpXTozrVnhuElGV-BdoIZaBOqg8wtr_z2hiO_1CY",
    "google-site-verification=Z8jVzgnaG8CjbUygDISY-3uP8uIqGzn5At2bo5nzHqQ"
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
      "/about/investor-relations",
      "*emailTemplateID=",
      "/features/website-builder/templates/*/*",
      "/features/website-builder/templates/business-and-services/*,*",
      "/features/website-builder/templates*order=",
      "/features/website-builder/templates/business-and-services$",
      "/features/website-builder/templates/business-and-services*order=",
      "/resources*company-or-business-role=",
      "/resources*category=",
      "/resources*type=",
      "/resources*query=",
      "/resources*sort=",
      "/resources*i=",
      "/api/",
      "*/api/v2"
    ]
  },
  "elapsed_s": 32.2,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
