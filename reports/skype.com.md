# Security Audit Report — skype.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://skype.com/ |
| Bug bounty program | Microsoft Online Services |
| Listed scope domain | skype.com |
| Test date | 2026-09-26 23:38 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

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
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 17 | low | H21 | HSTS does not cover subdomains | CWE-319 |

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

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=R9lBFA5SoH0CKpHuBMa4akNqb8E8YF8fim8qpGF22mg; facebook-domain-verification=87pranlm54pxjnpg1lp1nc3bcanv3f
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://oneocsp.microsoft.com/ocsp -> http-400
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but skype.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The skype.com certificate lists an AIA OCSP responder (http://oneocsp.microsoft.com/ocsp) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 17. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on skype.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of skype.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

## Evidence (raw response observations)

```json
{
  "domain": "skype.com",
  "dns": {
    "a": [
      "20.231.239.246",
      "20.236.44.162",
      "20.70.246.20",
      "20.112.250.133",
      "20.76.201.171"
    ],
    "aaaa": [
      "2603:1020:201:10::10f",
      "2603:1010:3:3::5b",
      "2603:1030:20e:3::23c",
      "2603:1030:c02:8::14",
      "2603:1030:b:3::152"
    ],
    "cname": null,
    "mx": [
      "skype-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns4-205.azure-dns.info.",
      "ns1-205.azure-dns.com.",
      "ns3-205.azure-dns.org.",
      "ns2-205.azure-dns.net."
    ],
    "caa": [
      "0 issue \"globalsign.com\"",
      "0 contactemail \"caarecordaware@microsoft.com\"",
      "0 issue \"microsoft.com\"",
      "0 issue \"digicert.com\""
    ],
    "spf": [
      "v=msv1 t=6097A7EA-53F7-4028-BA76-6869CB284C54",
      "google-site-verification=R9lBFA5SoH0CKpHuBMa4akNqb8E8YF8fim8qpGF22mg",
      "facebook-domain-verification=87pranlm54pxjnpg1lp1nc3bcanv3f",
      "v=spf1 include:_spf-ssg-a.microsoft.com ip4:91.190.218.48 ip4:91.190.216.100 -all"
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
    "days_left": 77,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "20.231.239.246",
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=R9lBFA5SoH0CKpHuBMa4akNqb8E8YF8fim8qpGF22mg",
    "facebook-domain-verification=87pranlm54pxjnpg1lp1nc3bcanv3f"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.12",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": "http://oneocsp.microsoft.com/ocsp",
      "serial": 1628027556611420636777166132317051953043930444,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://www.microsoft.com/pkiops/crl/partition/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%2010_Partition00085.crl",
        "http://crl2.microsoft.com/pkiops/crl/partition/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%2010_Partition00085.crl"
      ],
      "subject_dn": "310b3009060355040613025553310b30090603550408130257413110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e311b301906035504031312766964656f627265616b646f776e2e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312830260603550403131f4d6963726f736f667420544c5320473220525341204341204f435350203130",
      "not_before": "20260904080527",
      "not_after": "20261213070527"
    },
    "ocsp": "http-400"
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.skype.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=31536000",
    "crl": {
      "url": "http://www.microsoft.com/pkiops/crl/partition/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%2010_Partition00085.crl",
      "status": 200
    }
  },
  "elapsed_s": 36.3,
  "rechecked": "2026-09-26 23:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- Findings are reported against the public program scope; submission through the program tracker is pending.
