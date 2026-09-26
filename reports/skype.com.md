# Security Audit Report — skype.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://skype.com/ |
| Bug bounty program | Microsoft Online Services |
| Listed scope domain | skype.com |
| Test date | 2026-09-25 10:15 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

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

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Kestrel
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
- **Detail:** Header reveals: Kestrel
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "skype.com",
  "dns": {
    "a": [
      "20.112.250.133",
      "20.70.246.20",
      "20.231.239.246",
      "20.76.201.171",
      "20.236.44.162"
    ],
    "aaaa": [
      "2603:1030:20e:3::23c",
      "2603:1020:201:10::10f",
      "2603:1030:c02:8::14",
      "2603:1010:3:3::5b",
      "2603:1030:b:3::152"
    ],
    "cname": null,
    "mx": [
      "skype-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns2-205.azure-dns.net.",
      "ns4-205.azure-dns.info.",
      "ns3-205.azure-dns.org.",
      "ns1-205.azure-dns.com."
    ],
    "spf": [
      "v=spf1 include:_spf-ssg-a.microsoft.com ip4:91.190.218.48 ip4:91.190.216.100 -all",
      "google-site-verification=R9lBFA5SoH0CKpHuBMa4akNqb8E8YF8fim8qpGF22mg",
      "facebook-domain-verification=87pranlm54pxjnpg1lp1nc3bcanv3f",
      "v=msv1 t=6097A7EA-53F7-4028-BA76-6869CB284C54"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:rua@dmarc.microsoft,mailto:skype@rua.netcraft.com; fo=1; ruf=mailto:rua@dmarc.microsoft,mailto:skype@ruf.netcraft.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=WA, localityName=Redmond, organizationName=Microsoft Corporation, commonName=videobreakdown.com",
    "issuer": "countryName=US, organizationName=Microsoft Corporation, commonName=Microsoft TLS G2 RSA CA OCSP 10",
    "notBefore": "Sep  4 08:05:27 2026 GMT",
    "notAfter": "Dec 13 07:05:27 2026 GMT",
    "san": [
      "videobreakdown.com",
      "edge.ms",
      "msphu.net",
      "skype.com",
      "skype.net",
      "dynamics.cz",
      "dynamics.eu",
      "cosmosdb.com",
      "indexnow.org",
      "powerapps.io",
      "dynamics.asia",
      "fsinsider.com",
      "gpu.azure.com",
      "microsoft.org",
      "play.gears.gg",
      "powerapps.com",
      "*.microsoft.ch",
      "bingplaces.com",
      "docs.azure.com",
      "dynamics365.ae",
      "dynamics365.at",
      "dynamics365.ch",
      "dynamics365.cl",
      "dynamics365.co",
      "dynamics365.cz",
      "dynamics365.dk",
      "dynamics365.ec",
      "dynamics365.es",
      "dynamics365.eu",
      "dynamics365.fr",
      "dynamics365.hk",
      "dynamics365.in",
      "dynamics365.it",
      "dynamics365.lt",
      "dynamics365.mx",
      "dynamics365.nz",
      "dynamics365.pt",
      "dynamics365.ro",
      "dynamics365.ru",
      "dynamics365.se",
      "dynamics365.us",
      "dynamics365.vn",
      "fsxinsider.com",
      "dynamics.com.tr",
      "dynamics365.com",
      "www.dynamics.cz",
      "www.dynamics.eu",
      "msfttransform.ca",
      "redtigerwiki.com",
      "www.dynamics.com",
      "www.powerapps.io",
      "clearsoftware.com",
      "make.dynamics.com",
      "meetfasttrack.com",
      "microsoftstore.ca",
      "reports.azure.com",
      "www.dynamics.asia",
      "www.microsoft.org",
      "www.powerapps.com",
      "businesscentral.be",
      "businesscentral.ch",
      "businesscentral.jp",
      "businesscentral.mx",
      "businesscentral.tw",
      "businesscentral.us",
      "graph.microsoft.io",
      "hololensevents.com",
      "microsoftstore.com",
      "partner.office.com",
      "www.dynamics365.ae",
      "www.dynamics365.at",
      "www.dynamics365.ch",
      "www.dynamics365.cl",
      "www.dynamics365.co",
      "www.dynamics365.cz",
      "www.dynamics365.dk",
      "www.dynamics365.ec",
      "www.dynamics365.es",
      "www.dynamics365.eu",
      "www.dynamics365.fr",
      "www.dynamics365.hk",
      "www.dynamics365.in",
      "www.dynamics365.it",
      "www.dynamics365.lt",
      "www.dynamics365.mx",
      "www.dynamics365.nz",
      "www.dynamics365.pt",
      "www.dynamics365.ro",
      "www.dynamics365.ru",
      "www.dynamics365.se",
      "www.dynamics365.us",
      "www.dynamics365.vn",
      "www.fsxinsider.com",
      "*.microsoftedge.com",
      "drumbeat.office.com",
      "storageexplorer.com",
      "www.dynamics.com.tr",
      "www.dynamics365.com",
      "resnet.microsoft.com",
      "windowsondevices.com",
      "www.msfttransform.ca",
      "myready.microsoft.com",
      "www.clearsoftware.com",
      "www.meetfasttrack.com",
      "www.microsoftstore.ca",
      "designedforsurface.com",
      "make.powerplatform.com",
      "ude.corp.microsoft.com",
      "www.businesscentral.be",
      "www.businesscentral.ch",
      "www.businesscentral.jp",
      "www.businesscentral.mx",
      "www.businesscentral.tw",
      "www.businesscentral.us",
      "www.hololensevents.com",
      "tryazuremarketplace.com",
      "www.storageexplorer.com",
      "pocresnetv.microsoft.com",
      "windowsforiotdevices.com",
      "www.windowsondevices.com",
      "batchaitraining.azure.com",
      "ude.support.microsoft.com",
      "ccsmtogether.microsoft.com",
      "collegepuzzlechallenge.com",
      "www.designedforsurface.com",
      "www.tryazuremarketplace.com",
      "www.windowsforiotdevices.com",
      "digestibledynamicspodcast.com",
      "dynamics365businesscentral.be",
      "dynamics365businesscentral.ca",
      "dynamics365businesscentral.ch",
      "www.collegepuzzlechallenge.com",
      "support.microsoftaffiliates.com",
      "dynamics365businesscentral.co.nz",
      "dynamics365businesscentral.co.za",
      "thedigestibledynamicspodcast.com",
      "dynamics365businesscentral.com.au",
      "www.digestibledynamicspodcast.com",
      "www.dynamics365businesscentral.be",
      "www.dynamics365businesscentral.ca",
      "www.dynamics365businesscentral.ch",
      "www.dynamics365businesscentral.co.nz",
      "www.dynamics365businesscentral.co.za",
      "www.thedigestibledynamicspodcast.com",
      "hwp.sfec.microsoft.com",
      "hwp.sfecuat.microsoft.com",
      "ambitions.microsoft.fr",
      "mapmenumerique.microsoft.fr",
      "spark.windows",
      "www.spark.windows",
      "lumenisity.com",
      "www.lumenisity.com",
      "samples.bingmapsportal.com",
      "turing.microsoft.com",
      "iis.net",
      "asp.net",
      "referencesource.microsoft.com",
      "documentdb.io",
      "www.tealsk12.org",
      "tealsk12.org",
      "solutions.microsoft.com",
      "www.solutions.microsoft.com",
      "test.solutions.microsoft.com",
      "eduinsights.int.microsoft.com",
      "partnerinnovation.microsoft.com",
      "ageofmythology.com",
      "www.ageofmythology.com",
      "mlz.app",
      "www.mlz.app",
      "trym365copilot.com",
      "www.trym365copilot.com",
      "natick.research.microsoft.com"
    ],
    "days_left": 78,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "20.112.250.133",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Kestrel"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.skype.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.skype.com/"
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 35.7,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
