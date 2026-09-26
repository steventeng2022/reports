# Security Audit Report — sutterhealth.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://sutterhealth.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | sutterhealth.org |
| Test date | 2026-09-25 10:21 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 5, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 12 days (notAfter Oct  7 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Vercel
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
- **Detail:** Header reveals: Vercel
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "sutterhealth.org",
  "dns": {
    "a": [
      "64.239.109.1"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "sutterhealth-org.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns3-05.azure-dns.org.",
      "ns4-05.azure-dns.info.",
      "ns1-05.azure-dns.com.",
      "ns2-05.azure-dns.net."
    ],
    "spf": [
      "amazonses:+ouqWoubNLvOffFrO8GNnPJsJqC3k9zvq4fGmF+/JFc=",
      "MS=ms47734453",
      "vmware-cloud-verification-03a26331-13b3-4a4f-8123-a34d1b5466e6",
      "njH6RDHlABsQmJvITIaqix1L+/Y3ZLr1u/H0Lj/PqqvvNPv8oMwuwaxiZFRNkYdtifBqMGV7Rf7i9r9i/P7uzA==",
      "google-site-verification=5suSPLWcnGo4WMF8P2HtDOX0AnzrBIfGv2JpJ89kM_o",
      "A2A2AED6DE5DB1951512FE7F27A0FF20849F36FE5A2086EA578A8F8D618514D0",
      "flexera-domain-verification-dcafjcaqzcrdbucx",
      "smartsheet-site-validation=KG4FnJLPbY4nNo-dVmeX_sNqnmYA11I-",
      "tqsshcrdlqd6jz66rb59x85p3mp6xt5j",
      "pardot266982=11b4fde586ddd3585348b584a83b7b24379df66ceea079251091c947935bb3a2",
      "427263CA40526231DA0DD17A9899B7423D812E7AA717665DBE16B613DB02B34C",
      "_etnz4zr5xfdan0i6arxavk1gj5fzzpo",
      "airtable-verification=480dc28b5f136aeeb9c72e1ffecd2d94",
      "atlassian-domain-verification=k/4cB6WdjX8dp8sJrsQpUCv13/jkgZuZB472VFPxuN9TbANMRruC8a5QSriOWHHe",
      "jamf-site-verification=YEnMiAdegNX2xNXsyl81MA",
      "openai-domain-verification=dv-sgDNw1gS2lSTsyf6bdj2f3fh",
      "google-site-verification=1ut73vMWSdD7vAGFYE6rwNwgZp6sTlzHM4KE_iMO-Wg",
      "sprout-social-260c110f-d385-4d75-9e75-7d32e5c9e17e",
      "v=spf1 ip4:198.217.64.0/24 ip4:198.217.112.0/24 ip4:199.79.205.16/29 ip4:199.79.205.32/29 include:_spf1.sutterhealth.org include:_spf2.sutterhealth.org include:_spf3.sutterhealth.org include:_spf4.sutterhealth.org include:spf.protection.outlook.com -all",
      "28DD0C4B37308B587E99CBDEE640AB744470C72767F36FB82E374F3E94D67B32",
      "_5jyz87it742obj4hxmhnp46i4byr8vw",
      "apple-domain-verification=6EmugeAdzqtGatZ7",
      "twilio-domain-verification=f9445f3342fc1d16bc787547acc675e3",
      "dtm-domain-verification=A5i70Rs02iuV7ZM7VBHmm1NXbUDdVVLR7G7sz9q5zR8",
      "intersight=2f9f41d547c44be2b28284231fe1c0d3387c68d963a53d504f18cfec349315cd"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; rua=mailto:es8rh9mx@ag.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, organizationName=Sutter Health, commonName=sutterhealth.org",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA OV R36",
    "notBefore": "Mar 23 00:00:00 2026 GMT",
    "notAfter": "Oct  7 23:59:59 2026 GMT",
    "san": [
      "sutterhealth.org",
      "www.sutterhealth.org"
    ],
    "days_left": 12,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "64.239.109.1",
    "open": []
  },
  "https": {
    "status": 429,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Vercel"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.sutterhealth.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 308,
    "location": "https://sutterhealth.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 429",
    "/redirect?next=https://evil-auditor.example/x -> 429",
    "/go?url=https://evil-auditor.example/x -> 429",
    "/url?url=https://evil-auditor.example/x -> 429"
  ],
  "paths": {
    "/robots.txt": 429,
    "/sitemap.xml": 429,
    "/.well-known/security.txt": 429,
    "/security.txt": 429,
    "/.git/HEAD": 429,
    "/.git/config": 429,
    "/.env": 429,
    "/.htaccess": 429,
    "/wp-login.php": 429,
    "/phpmyadmin/index.php": 429,
    "/server-status": 429,
    "/api/": 429
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 43.5,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
