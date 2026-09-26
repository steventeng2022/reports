# Security Audit Report — webmd.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://webmd.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | webmd.com |
| Test date | 2026-09-26 17:55 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 5, Info: 11)

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
| 11 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache
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
- **Detail:** Header reveals: Apache
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: facebook-domain-verification=w0zj3kf18imt845aplzy38efaox23t; google-site-verification=XIEa3Mj4EhHxjtJ0RrN1tSfKYwyPFKyhoKFKZrfTn3Y; adobe-idp-site-verification=273cee5ce44db359754043668120f4ccf0076e55a5fe663ce1bc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of webmd.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 27 disallow path(s), e.g. */search/search_results/, /500, /aim/, /api/, /bipolar-disorder/video/bipolar-fatherhood
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "webmd.com",
  "dns": {
    "a": [
      "207.231.204.56"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "vita.ns.cloudflare.com.",
      "amir.ns.cloudflare.com."
    ],
    "spf": [
      "facebook-domain-verification=w0zj3kf18imt845aplzy38efaox23t",
      "google-site-verification=XIEa3Mj4EhHxjtJ0RrN1tSfKYwyPFKyhoKFKZrfTn3Y",
      "adobe-idp-site-verification=273cee5ce44db359754043668120f4ccf0076e55a5fe663ce1bced543f24d765",
      "s6fk0y05g78y03fjjkwynkb69sf9ggbb",
      "a65ccd5662904680b467ccd142e9670b",
      "wrike-verification=MTkwMjI3MDo2ZmJlNDE2N2FiMzllNjE0MDdiYjJjN2NmOWE2ZDA5YTA4YzliZjM5MThiNmQ3MWI5YTk4YmI4OTk5Y2QyMWZm",
      "google-site-verification=BR_G5pH8GUkbNgoC1nOdBpj3UZINgHU5Q9KltDsEGBM",
      "globalsign-domain-verification=-8kpivpbgMACeanB8hk0ansSLujEnFA_i1ukkwKY1Y",
      "google-site-verification=tbLtuRpVup8Z965hPBFprdgjOoJw4VJqv1mkzJl84VE",
      "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAglkiu3gC0LOVJ8uWLfw8Ykk9tEFFL/EdXmMFBDUZSHMtPKRG0LBUBsmV/piNw1xsjg+nR3zpqqu68DeV/2GnFTvcKu02YJS7B6T7ibL/One14BoZW5Hpdp2LEnQxmrMxGjlzZHvwI9+3w9qgpo1jCe34jKW2pr6ext5cX7SxyNO41c5l4QgI4oJu3GGq2l6CM",
      "N+OJAc54GU4ofetwS+L8gcWK86+ebMilGq3OgpowJZATl27ii7KiIHxZXixNLB5nDVPKrmuN4jcYEYGPEVELK4X/NxZWGTiZoFRXxwTDZYaBrDyxvOoFbQqwwOHfrMHHwTSTSRH5eLp2CGmMQtutwIDAQAB",
      "_7ef7fpwy2w82xju83yg53s3475e2qvn",
      "v=spf1 include:spf.zohomail360.com include:mail.zendesk.com include:spf.protection.outlook.com include:_spf.google.com include:spf.mandrillapp.com ip4:207.138.251.0/25 ip4:104.47.37.127 ip4:12.237.176.1/24 ip4:13.108.238.128/27 ip4:13.108.254.128/27 ip4:1",
      "36.146.208.16/28 ip4:136.146.210.16/28 ip4:136.147.46.176/28 ip4:136.147.46.224/26 ip4:136.147.62.176/28 ip4:136.147.62.224/26 ip4:204.14.232.64/28 ip4:204.14.234.64/28 ip4:206.155.74.1/24 ip4:207.231.200.0/21 ip4:213.199.154.0/17 ip4:216.32.180.0/23 ip4:",
      "23.253.183.0/24 ip4:63.150.153.0/28 ip4:63.236.105.192/28 ip4:63.236.106.128/27 ip4:63.236.109.192/28 ip4:63.236.97.64/27 ip4:64.113.28.0/22 ip4:65.121.87.1/24 ip4:65.55.88.0/24 ip4:66.179.21.130 ip4:67.130.38.1/24 ip4:68.177.111.128/26 ip4:96.43.144.64/2",
      "8 ip4:96.43.147.64/28 ip4:96.43.148.64/28 ip4:96.43.151.64/28 ip4:208.185.229.0/24 ip4:208.185.235.0/24 ip4:148.59.108.0/24 ip4:148.59.106.0/24 ip4:40.71.34.249 ip4:98.158.192.0/20 ~all",
      "google-site-verification=8ndI6dMiz3lrBkg2YbMR_RMa3lihncz9VgamtujOXQo",
      "e0cfe10a46f74485a608c50a63f263f9",
      "SFMC-OzW5wNjIBpdXFIg-AnBOn39Kj0umwTThgg5Yfwm7",
      "v=DKIM1; k=rsa; p=MIIBIjANB\" \"gkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAglkiu3gC0LOVJ8uWLfw8Ykk9tEFFL/EdXmMFBDUZSHMtPKRG0LBUBsmV/piNw1xsjg+nR3zpqqu68DeV/2GnFTvcKu02YJS7B6T7ibL/One14BoZW5Hpdp2LEnQxmrMxGjlzZHvwI9+3w9qgpo1jCe34jKW2pr6ext5cX7SxyNO41c5l4QgI4oJu3GGq2l",
      "6CMN+OJAc54GU4ofetwS+L8gcWK86\" \"+ebMilGq3OgpowJZATl27ii7KiIHxZXixNLB5nDVPKrmuN4jcYEYGPEVELK4X/NxZWGTiZoFRXxwTDZYaBrDyxvOoFbQqwwOHfrMHHwTSTSRH5eLp2CGmMQtutwIDAQAB",
      "google-site-verification=WUMAoNjAhtgdb0eWxrQUo1aE3Rvz4ApU-CRm0Dtw1-A"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:1dda25c86b124ea4bf939c3c9714ee43@dmarc-reports.cloudflare.net,mailto:dmarcreport@webmd.com; fo=1; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=le.prod.webmd.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Sep  2 00:10:04 2026 GMT",
    "notAfter": "Dec  1 00:10:03 2026 GMT",
    "san": [
      "*.derigo.us",
      "*.framesdata.com",
      "*.krames.com",
      "*.kramesondemand.com",
      "*.kramesonline.com",
      "*.kramesstaywell.com",
      "*.kramesvideo.com",
      "*.la1.webmd.com",
      "*.m.webmd.com",
      "*.ma1.krames.com",
      "*.ma1.kramesondemand.com",
      "*.ma1.kramesonline.com",
      "*.ma1.kramesstaywell.com",
      "*.ma1.kramesvideo.com",
      "*.ma1.medicinenet.com",
      "*.ma1.staywellhealthlibrary.com",
      "*.ma1.staywellknowledgebase.com",
      "*.ma1.staywellsolutionsonline.com",
      "*.ma1.webmd.com",
      "*.medicinenet.com",
      "*.mediquality.net",
      "*.medscape.com",
      "*.medscape.org",
      "*.medscapestatic.com",
      "*.mngh.co",
      "*.myframegallery.com",
      "*.preview.m.webmd.com",
      "*.preview.webmd.com",
      "*.proddev.medscape.com",
      "*.proddev.medscape.org",
      "*.proddev.medscapestatic.com",
      "*.staging.krames.com",
      "*.staging.kramesondemand.com",
      "*.staging.kramesonline.com",
      "*.staging.kramesstaywell.com",
      "*.staging.kramesvideo.com",
      "*.staging.m.webmd.com",
      "*.staging.medscape.com",
      "*.staging.medscape.org",
      "*.staging.medscapestatic.com",
      "*.staging.staywellhealthlibrary.com",
      "*.staging.staywellknowledgebase.com",
      "*.staging.staywellsolutionsonline.com",
      "*.staging.webmd.com",
      "*.staywellhealthlibrary.com",
      "*.staywellknowledgebase.com",
      "*.staywellsolutionsonline.com",
      "*.stg-ma1.kramesondemand.com",
      "*.stg-ma1.kramesonline.com",
      "*.stg-ma1.kramesstaywell.com",
      "*.stg-ma1.kramesvideo.com",
      "*.stg-ma1.staywellhealthlibrary.com",
      "*.stg-ma1.staywellknowledgebase.com",
      "*.stg-ma1.staywellsolutionsonline.com",
      "*.stprod.webmd.com",
      "*.webmd.com",
      "derigo.us",
      "fdb.rxlist.com",
      "framesdata.com",
      "images.emedicinehealth.com",
      "images.onhealth.com",
      "images.rxlist.com",
      "img.medscape.fr",
      "img.medscapemedizin.de",
      "kramesondemand.com",
      "kramesonline.com",
      "kramesvideo.com",
      "le.prod.webmd.com",
      "medicinenet.com",
      "medscape.com",
      "medscape.org",
      "mngh.co",
      "mobilebeta.webmdpartner.net",
      "sf2aim.webmd.net",
      "staging.mobileconnections.webmd.com",
      "staging.patientjourneys.webmd.com",
      "staywellknowledgebase.com",
      "staywellsolutionsonline.com",
      "webmd.com",
      "www.doctor.webmd.com",
      "www.emedicinehealth.com",
      "www.onhealth.com",
      "www.rxlist.com",
      "www.sponsorcontent.webmd.com",
      "www.symptomchecker.webmd.com"
    ],
    "days_left": 65,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "207.231.204.56",
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
  "cookies": [
    {}
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.webmd.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.webmd.com/"
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
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
    "/.git/HEAD": 403,
    "/.git/config": 403,
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
    "facebook-domain-verification=w0zj3kf18imt845aplzy38efaox23t",
    "google-site-verification=XIEa3Mj4EhHxjtJ0RrN1tSfKYwyPFKyhoKFKZrfTn3Y",
    "adobe-idp-site-verification=273cee5ce44db359754043668120f4ccf0076e55a5fe663ce1bc",
    "wrike-verification=MTkwMjI3MDo2ZmJlNDE2N2FiMzllNjE0MDdiYjJjN2NmOWE2ZDA5YTA4YzliZ",
    "google-site-verification=BR_G5pH8GUkbNgoC1nOdBpj3UZINgHU5Q9KltDsEGBM"
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
  "http2": {
    "robots_disallow": [
      "*/search/search_results/",
      "/500",
      "/aim/",
      "/api/",
      "/bipolar-disorder/video/bipolar-fatherhood",
      "/bipolar-disorder/video/bipolar-toolbox",
      "/breast-cancer/bc-treatment-21/provider-select",
      "/click*",
      "/dna",
      "/drugs/2/search*",
      "/drugs/ReportAbuse.aspx*",
      "/kapi/",
      "/mm/",
      "/my-library",
      "/news/header.php"
    ]
  },
  "elapsed_s": 31.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
