# Security Audit Report — espn.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://espn.com/ |
| Bug bounty program | The Walt Disney Company |
| Listed scope domain | espn.com |
| Test date | 2026-09-26 18:50 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 5, Info: 17)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 13 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 19 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 20 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 21 | info | CT1 | 118 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 22 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 13. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.espn.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 14. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 15. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 16. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: cisco-ci-domain-verification=48652156c723cc0989fbc1c14af4f05c20b2c7b50fa948e499c; ciscocidomainverification=2c2658d02e94ce88b29494db432d2c911fc43abd373e5e485b5856; dropbox-domain-verification=f8opl8j5mr5e
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of espn.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 19. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 113 disallow path(s), e.g. /, /, /, /, /
- **Recommendation:** Review disallowed paths; robots is not access control.

### 20. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 54.192.248.80 carries PTR server-54-192-248-80.tpe53.r.cloudfront.net. for espn.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 21. [INFO] 118 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: affiliate.api.qa.espn.com, artwork.api.qa.espn.com, assets.espn.com, cdp-nifi-eks-prod.aws.dp.hosted.espn.com, dcs7deportes-preview.us-west-2.aws.internal.espn.com, dcs7deportes.us-west-2.aws.internal.espn.com, dcs7domestic-preview.us-west-2.aws.internal.espn.com, dcs7domestic.us-west-2.aws.internal.espn.com, dcs7espn3.us-west-2.aws.internal.espn.com, dcs7soccernet-preview.us-west-2.aws.internal.espn.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 22. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: affiliate.api.qa.espn.com, cdp-nifi-eks-prod.aws.dp.hosted.espn.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "espn.com",
  "dns": {
    "a": [
      "54.192.248.80",
      "54.192.248.14",
      "54.192.248.40",
      "54.192.248.106"
    ],
    "aaaa": [
      "2600:9000:202f:ee00:d:ac18:e2c0:93a1",
      "2600:9000:202f:4200:d:ac18:e2c0:93a1",
      "2600:9000:202f:1000:d:ac18:e2c0:93a1",
      "2600:9000:202f:a400:d:ac18:e2c0:93a1",
      "2600:9000:202f:9200:d:ac18:e2c0:93a1",
      "2600:9000:202f:8a00:d:ac18:e2c0:93a1",
      "2600:9000:202f:7c00:d:ac18:e2c0:93a1",
      "2600:9000:202f:800:d:ac18:e2c0:93a1"
    ],
    "cname": null,
    "mx": [
      "espn-com.mail.protection.outlook.com (pref 5)"
    ],
    "ns": [
      "ns-1045.awsdns-02.org.",
      "ns-122.awsdns-15.com.",
      "ns-1936.awsdns-50.co.uk.",
      "ns-846.awsdns-41.net."
    ],
    "spf": [
      "cisco-ci-domain-verification=48652156c723cc0989fbc1c14af4f05c20b2c7b50fa948e499ca824f79f41b69",
      "ciscocidomainverification=2c2658d02e94ce88b29494db432d2c911fc43abd373e5e485b58562f8dd78c80",
      "dropbox-domain-verification=f8opl8j5mr5e",
      "canva-site-verification=WmByBdRldeLifoeVTzfTgA",
      "extensis-domain-verification=17bb048b-06af-47a8-b8e5-d4a1155683c7",
      "asv=1cfe02e3a81e8e65022ac143e0107fdd",
      "adobe-idp-site-verification=bb3da93fff816c4b9c75b5b87e7afbf88dff2c0dce3c5d8f6357552992c65903",
      "v=spf1 include:servers.mcsv.net mx ip4:74.123.203.125 ip4:74.123.200.120 ip4:74.123.200.35 ip4:74.123.200.36 ip4:74.123.203.98 ip4:74.123.200.222 ip4:192.234.2.39 include:_spf.emailcampaigns.net include:userinclude.dme3ds1.com include:spf.disney.com ~all",
      "google-gws-recovery-domain-verification=41057864",
      "google-site-verification=DM1CrNK7K2cq6YvNdmMPeIZBNQxxqw0a6ENutWnHoJQ",
      "google-site-verification=d5RkNYJAq7RNqkZUNx-NjrdsUxYH77Qs7zl2ZqRj2Sc",
      "facebook-domain-verification=0y89pokpwmy3a9yqhuqx0wg8r23l9p",
      "pzhuVdOHPcxbY0BufDtyUHwrXoU8KikclnWWDgxOWNCyyCXtpK1Ws+A4mpps+Rtq0GARiBCA+IVLiCYcDhlSLw==",
      "adobe-idp-site-verification=012b7d24aff9766444b9232173abb52ef026139e50aac77c49e02bd5d0dc3916",
      "D074-DF5F-73F8-42A6-65B8-DCED-DDCF-F835",
      "docusign=0f5ff8fc-4420-4d52-9877-33f1485d191f",
      "MS=ms54940749",
      "atlassian-domain-verification=5lqJwtfJPMHqC/aGvT/7s2BR53IHCs9P6vFjCQYA5nkQ4mvoHKTqNTW7gucscGW7",
      "q1sjrk62qcsk7u2g2q8f46lhp",
      "docusign=e95b2d67-24b3-4e1e-9402-902d0b5e0c63",
      "smartsheet-site-validation=vnu8x72WuY2SpP5LfwpJ3QEgKvaywdIx"
    ],
    "dmarc": [
      "v=DMARC1;p=none;fo=1;rua=mailto:Corp.Dmarc_RUA@disney.com;ruf=mailto:Corp.Dmarc_RUF@disney.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, organizationName=The Walt Disney Company, commonName=editions.espn.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA OV R36",
    "notBefore": "Nov 10 00:00:00 2025 GMT",
    "notAfter": "Nov 10 23:59:59 2026 GMT",
    "san": [
      "editions.espn.com",
      "*.api.espn.cl",
      "*.api.espn.co.cr",
      "*.api.espn.co.uk",
      "*.api.espn.com.ar",
      "*.api.espn.com.au",
      "*.api.espn.com.br",
      "*.api.espn.com.co",
      "*.api.espn.com.do",
      "*.api.espn.com.ec",
      "*.api.espn.com.gt",
      "*.api.espn.com.mx",
      "*.api.espn.com.pa",
      "*.api.espn.com.pe",
      "*.api.espn.com.sg",
      "*.api.espn.com.uy",
      "*.api.espn.com.ve",
      "*.api.espn.es",
      "*.api.espn.in",
      "*.api.espn.nl",
      "*.espn.cl",
      "*.espn.co.cr",
      "*.espn.co.uk",
      "*.espn.com",
      "*.espn.com.ar",
      "*.espn.com.au",
      "*.espn.com.br",
      "*.espn.com.co",
      "*.espn.com.do",
      "*.espn.com.ec",
      "*.espn.com.gt",
      "*.espn.com.mx",
      "*.espn.com.pa",
      "*.espn.com.pe",
      "*.espn.com.sg",
      "*.espn.com.uy",
      "*.espn.com.ve",
      "*.espn.es",
      "*.espn.go.com",
      "*.espn.in",
      "*.espn.nl",
      "*.espn.ph",
      "*.espndeportes.com",
      "*.fan.api.espn.co.cr",
      "*.fan.api.espn.com.do",
      "*.fan.api.espn.com.ec",
      "*.fan.api.espn.com.gt",
      "*.fan.api.espn.com.pa",
      "*.fan.api.espn.com.pe",
      "*.fan.api.espn.com.sg",
      "*.fan.api.espn.com.uy",
      "*.fan.api.espn.com.ve",
      "*.fan.api.espn.es",
      "*.fan.api.espn.nl",
      "*.fan.api.espn.ph",
      "espn.cl",
      "espn.co.cr",
      "espn.co.uk",
      "espn.com",
      "espn.com.ar",
      "espn.com.au",
      "espn.com.br",
      "espn.com.co",
      "espn.com.do",
      "espn.com.ec",
      "espn.com.gt",
      "espn.com.mx",
      "espn.com.pa",
      "espn.com.pe",
      "espn.com.sg",
      "espn.com.uy",
      "espn.com.ve",
      "espn.es",
      "espn.go.com",
      "espn.in",
      "espn.nl",
      "espn.ph",
      "espndeportes.com",
      "fan.core.api.espn.cl",
      "fan.core.api.espn.co.cr",
      "fan.core.api.espn.co.uk",
      "fan.core.api.espn.com.ar",
      "fan.core.api.espn.com.au",
      "fan.core.api.espn.com.br",
      "fan.core.api.espn.com.co",
      "fan.core.api.espn.com.do",
      "fan.core.api.espn.com.ec",
      "fan.core.api.espn.com.gt",
      "fan.core.api.espn.com.mx",
      "fan.core.api.espn.com.pa",
      "fan.core.api.espn.com.pe",
      "fan.core.api.espn.com.sg",
      "fan.core.api.espn.com.uy",
      "fan.core.api.espn.com.ve",
      "fan.core.api.espn.es",
      "fan.core.api.espn.in",
      "fan.core.api.espn.nl",
      "fan.core.api.espn.ph"
    ],
    "days_left": 45,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.80",
    "open": []
  },
  "https": {
    "status": 202,
    "content_type": "text/html; charset=UTF-8",
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
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.espn.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 202
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 202",
    "/redirect?next=https://evil-auditor.example/x -> 202",
    "/go?url=https://evil-auditor.example/x -> 202",
    "/url?url=https://evil-auditor.example/x -> 202"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 202,
    "/.well-known/security.txt": 202,
    "/security.txt": 202,
    "/.git/HEAD": 202,
    "/.git/config": 202,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 202,
    "/phpmyadmin/index.php": 202,
    "/server-status": 202,
    "/api/": 202
  },
  "subdomains": {
    "source": "certspotter",
    "count": 118,
    "notable": [
      "affiliate.api.qa.espn.com",
      "artwork.api.qa.espn.com",
      "assets.espn.com",
      "cdp-nifi-eks-prod.aws.dp.hosted.espn.com",
      "dcs7deportes-preview.us-west-2.aws.internal.espn.com",
      "dcs7deportes.us-west-2.aws.internal.espn.com",
      "dcs7domestic-preview.us-west-2.aws.internal.espn.com",
      "dcs7domestic.us-west-2.aws.internal.espn.com",
      "dcs7espn3.us-west-2.aws.internal.espn.com",
      "dcs7soccernet-preview.us-west-2.aws.internal.espn.com",
      "dcs7soccernet.us-west-2.aws.internal.espn.com",
      "events.api.qa.espn.com",
      "guest-product-api.us-east-1.aws.hosted.espn.com",
      "guest-product-api.us-west-2.aws.hosted.espn.com",
      "image.mail.plus.espn.com"
    ],
    "sample": [
      "affiliate.api.qa.espn.com",
      "affiliate.disney.espn.com",
      "ak-hls-brs-espn1.espn.com",
      "ak-hls-brs-espn2.espn.com",
      "ak-hls-brs-espn3.espn.com",
      "ak-hls-brs-espnbbgl.espn.com",
      "ak-hls-brs-espndep.espn.com",
      "ak-hls-brs-espnews.espn.com",
      "ak-hls-brs-espnkhn.espn.com",
      "ak-hls-brs-espnlhn.espn.com",
      "ak-hls-brs-espnu.espn.com",
      "ak-hls-e3of-1.espn.com",
      "ak-hls-e3of-2.espn.com",
      "artwork.api.qa.espn.com",
      "assets.espn.com",
      "bc.video-origin.espn.com",
      "brsseavideo-ak.espn.com",
      "brsweb.video-origin.espn.com",
      "captiveportal-login.espn.com",
      "cd.espn.com"
    ],
    "dangling": [
      "affiliate.api.qa.espn.com",
      "cdp-nifi-eks-prod.aws.dp.hosted.espn.com"
    ]
  },
  "apex_txt": [
    "cisco-ci-domain-verification=48652156c723cc0989fbc1c14af4f05c20b2c7b50fa948e499c",
    "ciscocidomainverification=2c2658d02e94ce88b29494db432d2c911fc43abd373e5e485b5856",
    "dropbox-domain-verification=f8opl8j5mr5e",
    "canva-site-verification=WmByBdRldeLifoeVTzfTgA",
    "extensis-domain-verification=17bb048b-06af-47a8-b8e5-d4a1155683c7"
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
      "not_before": "20251110000000",
      "not_after": "20261110235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "*/admin/",
      "*/boxscore?",
      "*/calendar/",
      "*/cat/",
      "*/conversation?"
    ]
  },
  "x12": {
    "status": 202,
    "ptr": [
      "server-54-192-248-80.tpe53.r.cloudfront.net."
    ]
  },
  "elapsed_s": 4.3,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
