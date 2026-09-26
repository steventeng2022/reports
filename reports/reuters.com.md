# Security Audit Report — reuters.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://reuters.com/ |
| Bug bounty program | Reuters |
| Listed scope domain | reuters.com |
| Test date | 2026-09-26 14:55 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

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

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: BigIP
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
- **Detail:** Header reveals: BigIP
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "reuters.com",
  "dns": {
    "a": [
      "155.46.172.255"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-00160c04.gslb.pphosted.com (pref 10)",
      "mxb-00160c04.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-aws-2.thomsonreuters.net.",
      "ns-aws-3.thomsonreuters.org.",
      "ns-aws-1.thomsonreuters.com.",
      "ns-aws-4.thomsonreuters.co.uk."
    ],
    "spf": [
      "openai-domain-verification=dv-3vP8oxOY9pDhfiwzHjba8jmZ",
      "yahoo-verification-key=5bF6siWgzdkfub3ZLp8cnSL2ps44ipYuy28vgoM7qDA=",
      "apple-domain-verification=cKpm3aVB5VEf9fQ0oxIIumulcv3CvTjrOGvqF8nUDO8",
      "google-site-verification=7UwjlMmBYuyFWx01Pu6NEVEWRPD9W25PnwffZejseEg",
      "apple-domain-verification=voAz1fDhqIN4vRxG52m4VSOgLipH0OMyfJIprobVB1U",
      "google-site-verification=FZwUpO_E2LIEPLqcxfWRpQipxi2faQ4Qt4wyYJpJr1g",
      "facebook-domain-verification=ra7bjxso3pnjy2p63mdc0002chquca",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all",
      "google-site-verification=O1A9GoZ5a23atyZjR2IBMnmdG-jz3mrsQ900uMn0sbY",
      "MS=ms24417066",
      "google-site-verification=LMfrSuyToK_ofO0MSu-lf5QJhLYITHNDX09ofoF7_FY"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "countryName=CA, stateOrProvinceName=Ontario, organizationName=Thomson Reuters Corporation, commonName=thomsonreuters.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA OV R40",
    "notBefore": "Sep  3 00:00:00 2026 GMT",
    "notAfter": "Mar 20 23:59:59 2027 GMT",
    "san": [
      "thomsonreuters.com",
      "*.thomson.com",
      "*.tr.com",
      "arbsearch.com",
      "archbolde-update.co.uk",
      "blog.corepublishingsolutions.com",
      "breakingviews.com",
      "carswell.com",
      "caselines.com",
      "cfslaw.com",
      "checkpoint.cl",
      "checkpoint.com.pe",
      "checkpointau.com.au",
      "checkpointespana.es",
      "checkpointmexico.com",
      "checkpointnz.co.nz",
      "checkpointworld.com",
      "consumerbankruptcynews.com",
      "consumerbankruptcynews.net",
      "corepublishingsolutions.com",
      "courtexpress.com",
      "ctracknotification.ca",
      "ctracknotification.com",
      "cvmailasia.com",
      "cyberrisk-insurer.com",
      "editionsyvonblais.com",
      "es-insurer.com",
      "fastsalestax.com",
      "findandprint.com",
      "findprint.com",
      "gettaxnetpro.com",
      "gsionline.com",
      "highq.com",
      "hk-lawyer.org",
      "iblj.com",
      "impotexpert.ca",
      "incomesdata.co.uk",
      "informacionlegal.com.ar",
      "informacionlegal.com.uy",
      "informacionlegalonline.com.uy",
      "laley.com.ar",
      "laleynextonline.com.ar",
      "lawtel.com",
      "legalbusinessonline.com",
      "legalcurrent.com",
      "legalexecutiveinstitute.com",
      "litigationmonitor.com",
      "livenotecentral.com",
      "login.wbm-digital.com",
      "monitorsuite.com",
      "myaccount.wbm-digital.com",
      "myroyalty.com",
      "netlinksolution.com",
      "netlinksolutionqa.com",
      "newwestlaw.com",
      "oconnors.com",
      "odenpt.com",
      "odentrack.com",
      "onesourcelogin.com.au",
      "onesourcelogin.eu",
      "onesourcetax.com",
      "pagerohbs.com",
      "parametric-insurer.com",
      "personnet.com",
      "program-manager.com",
      "pubemplaw.com",
      "pubemplaw.net",
      "quickview.com",
      "reuters.co.uk",
      "reuters.com",
      "reuters.com.cn",
      "reuters.de",
      "reuters.es",
      "reuters.fr",
      "reuters.it",
      "reutersconnect.com",
      "revistadostribunais.com.br",
      "roundhall.ie",
      "rtonline.com.br",
      "safeguard.co.nz",
      "seccurrents.com",
      "securrents.com",
      "serengetilaw.com",
      "sureprep.com",
      "sustainable-insurer.com",
      "sweetandmaxwell.co.uk",
      "taxnetproplus.com",
      "theinsurer.com",
      "theinsurertv.com",
      "thomson.com",
      "thomsonreuters.ca",
      "thomsonreuters.cn",
      "thomsonreuters.co.jp",
      "thomsonreuters.co.kr",
      "thomsonreuters.co.nz",
      "thomsonreuters.com.au",
      "thomsonreuters.com.br",
      "thomsonreuters.com.hk",
      "thomsonreuters.com.my",
      "thomsonreuters.com.pe",
      "thomsonreuters.com.sg",
      "thomsonreuters.es",
      "thomsonreuters.in",
      "thomsonreutersmexico.com",
      "tr.com",
      "triform.com",
      "trymateria.ai",
      "ufile.ca",
      "ultratax.com",
      "wbm-digital.com",
      "westcheck.com",
      "westdoc.com",
      "westfindandprint.com",
      "westfindprint.com",
      "westlaw.co.nz",
      "westlaw.com",
      "westlaw.com.au",
      "westlaw.com.tw",
      "westlawasia.com",
      "westlawbusinesscurrents.com",
      "westlawchile.cl",
      "westlawclassic.com",
      "westlawcourtexpress.com",
      "westlawhub.com",
      "westlawinternational.com",
      "westlawjapan.com",
      "westlawnextcanada.com",
      "westlawprecision.com.au",
      "westlawpro.com",
      "westlawrewards.com",
      "westlawsolo.com",
      "westlawtoday.com",
      "westlawuk.com",
      "westmonitor.com",
      "wl-w.com",
      "www.archbolde-update.co.uk",
      "www.corepublishingsolutions.com",
      "www.cvmailasia.com",
      "www.cyberrisk-insurer.com",
      "www.editionsyvonblais.com",
      "www.es-insurer.com",
      "www.findandprint.com",
      "www.findprint.com",
      "www.gettaxnetpro.com",
      "www.iblj.com",
      "www.incomesdata.co.uk",
      "www.laley.com.ar",
      "www.lawtel.com",
      "www.legalcurrent.com",
      "www.legalexecutiveinstitute.com",
      "www.oconnors.com",
      "www.pagerohbs.com",
      "www.parametric-insurer.com",
      "www.program-manager.com",
      "www.reuters.com.cn",
      "www.reuters.de",
      "www.reuters.it",
      "www.serengetilaw.com",
      "www.sureprep.com",
      "www.sustainable-insurer.com",
      "www.taxnetproplus.com",
      "www.theinsurertv.com",
      "www.thomsonreuters.es",
      "www.triform.com",
      "www.trymateria.ai",
      "www.wbm-digital.com",
      "www.westfindandprint.com",
      "www.westfindprint.com",
      "www.westlaw.co.nz",
      "www.westlaw.com.au",
      "www.westlawinternational.com"
    ],
    "days_left": 175,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "155.46.172.255",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: BigIP"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.reuters.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.reuters.com/"
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
  "elapsed_s": 24.5,
  "rechecked": "2026-09-26 14:53 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
