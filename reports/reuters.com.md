# Security Audit Report — reuters.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://reuters.com/ |
| Bug bounty program | Reuters |
| Listed scope domain | reuters.com |
| Test date | 2026-09-26 18:58 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 6, Info: 14)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | low | RED10 | Host header reflected into redirect Location | CWE-601 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 19 | info | CT1 | 138 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 20 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=LMfrSuyToK_ofO0MSu-lf5QJhLYITHNDX09ofoF7_FY; google-site-verification=FZwUpO_E2LIEPLqcxfWRpQipxi2faQ4Qt4wyYJpJr1g; yahoo-verification-key=5bF6siWgzdkfub3ZLp8cnSL2ps44ipYuy28vgoM7qDA=
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of reuters.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [LOW] Host header reflected into redirect Location (`RED10`)

- **CWE:** CWE-601
- **Detail:** GET with Host: evil-auditor.example -> Location: https://www.evil-auditor.example/
- **Recommendation:** Validate redirect targets against the expected host.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 28 disallow path(s), e.g. /finance/stocks/option, /finance/stocks/financialHighlights, /search, /site-search/, /beta
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 155.46.172.255 carries PTR westlawclassic.com., go.thomson.com., westlawjapan.com., seccurrents.com., thomsonreuters.com., netlinksolution.com., es.thomson.com., westlaw.com.tw., westlawprecision.com.au., westlawhub.com., caselines.com., westlawinternational.com., cyberrisk-insurer.com., thomsonreuters.co.kr., reuters.co.uk., corepublishingsolutions.com., westlawnextcanada.com., laleynextonline.com.ar., tr.com., incomesdata.co.uk., thomsonreuters.com.pe., checkpointworld.com., thomsonreuters.in., onesourcelogin.eu., westcheck.com., roundhall.ie., findprint.com., odentrack.com., ultratax.com., triform.com., hk-lawyer.org., gsionline.com., thomsonreuters.com.au., arbsearch.com., cvmailasia.com., thomsonreuters.es., pagerohbs.com., thomsonreuters.com.br., checkpointnz.co.nz., impotexpert.ca., trymateria.ai., parametric-insurer.com., ufile.ca., thomsonreuters.co.jp., gettaxnetpro.com., westlawtoday.com., reutersconnect.com., westlawasia.com., monitorsuite.com., fastsalestax.com., thomsonreutersmexico.com., findandprint.com., onesourcetax.com., informacionlegal.com.uy., personnet.com., cs.thomson.com., pubemplaw.net., archbolde-update.co.uk., oconnors.com., thomsonreuters.ca., onesourcelogin.com.au., westdoc.com., checkpointespana.es., reuters.fr., thomson.com., wbm-digital.com., cfslaw.com., westlawbusinesscurrents.com., sureprep.com., westlawchile.cl., sweetandmaxwell.co.uk., netlinksolutionqa.com., legalcurrent.com., iblj.com., es-insurer.com., ctracknotification.com., reuters.com., ctracknotification.ca., thomsonreuters.com.hk., thomsonreuters.co.nz., westlaw.co.nz., theinsurertv.com., reuters.it., carswell.com., rtonline.com.br., litigationmonitor.com., breakingviews.com., thomsonreuters.cn., editionsyvonblais.com., wl-w.com., mypay.thomson.com., reuters.de., westlawpro.com., checkpoint.cl., westfindandprint.com., livenotecentral.com., safeguard.co.nz., legalbusinessonline.com., westfindprint.com., westlawsolo.com., westlawrewards.com., checkpoint.com.pe., sustainable-insurer.com., westlawcourtexpress.com., laley.com.ar., revistadostribunais.com.br., consumerbankruptcynews.com., westlaw.com., legalexecutiveinstitute.com., westlawuk.com., securrents.com., thomsonreuters.com.my., program-manager.com., checkpointau.com.au., checkpointmexico.com., westlaw.com.au., consumerbankruptcynews.net., courtexpress.com., westmonitor.com., thomsonreuters.com.sg., serengetilaw.com., informacionlegalonline.com.uy., reuters.com.cn., informacionlegal.com.ar., theinsurer.com., lawtel.com., reuters.es., newwestlaw.com., taxnetproplus.com., odenpt.com., myroyalty.com., quickview.com., pubemplaw.com. for reuters.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 19. [INFO] 138 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: apps.data.reuters.com, aws.contentdownloader.reuters.com, aws.dev.contentdownloader.reuters.com, aws.qa.contentdownloader.reuters.com, dev.ace.reuters.com, dev.commsmonitor.wne.reuters.com, dev.contentdownloader.reuters.com, dev.gpdb.media.reuters.com, dev.gpdbservices.media.reuters.com, dev.graphics.reuters.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 20. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: aws.dev.contentdownloader.reuters.com, dev.ace.reuters.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

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
      "mxb-00160c04.gslb.pphosted.com (pref 10)",
      "mxa-00160c04.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-aws-1.thomsonreuters.com.",
      "ns-aws-2.thomsonreuters.net.",
      "ns-aws-3.thomsonreuters.org.",
      "ns-aws-4.thomsonreuters.co.uk."
    ],
    "spf": [
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all",
      "google-site-verification=LMfrSuyToK_ofO0MSu-lf5QJhLYITHNDX09ofoF7_FY",
      "google-site-verification=FZwUpO_E2LIEPLqcxfWRpQipxi2faQ4Qt4wyYJpJr1g",
      "yahoo-verification-key=5bF6siWgzdkfub3ZLp8cnSL2ps44ipYuy28vgoM7qDA=",
      "google-site-verification=O1A9GoZ5a23atyZjR2IBMnmdG-jz3mrsQ900uMn0sbY",
      "openai-domain-verification=dv-3vP8oxOY9pDhfiwzHjba8jmZ",
      "apple-domain-verification=cKpm3aVB5VEf9fQ0oxIIumulcv3CvTjrOGvqF8nUDO8",
      "google-site-verification=7UwjlMmBYuyFWx01Pu6NEVEWRPD9W25PnwffZejseEg",
      "apple-domain-verification=voAz1fDhqIN4vRxG52m4VSOgLipH0OMyfJIprobVB1U",
      "MS=ms24417066",
      "facebook-domain-verification=ra7bjxso3pnjy2p63mdc0002chquca"
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
    "source": "certspotter",
    "count": 138,
    "notable": [
      "apps.data.reuters.com",
      "aws.contentdownloader.reuters.com",
      "aws.dev.contentdownloader.reuters.com",
      "aws.qa.contentdownloader.reuters.com",
      "dev.ace.reuters.com",
      "dev.commsmonitor.wne.reuters.com",
      "dev.contentdownloader.reuters.com",
      "dev.gpdb.media.reuters.com",
      "dev.gpdbservices.media.reuters.com",
      "dev.graphics.reuters.com",
      "dev.livesapi.wne.reuters.com",
      "dev.monitorapi.wne.reuters.com",
      "dev.stats.wne.reuters.com",
      "my.reuters.com",
      "ppe.videobroadcast.cdn.reuters.com"
    ],
    "sample": [
      "about.reuters.com",
      "ace.reuters.com",
      "adminportal-lab.reuters.com",
      "adminportal-qa.reuters.com",
      "adminportal.reuters.com",
      "agency.reuters.com",
      "apps.data.reuters.com",
      "aws.contentdownloader.reuters.com",
      "aws.dev.contentdownloader.reuters.com",
      "aws.qa.contentdownloader.reuters.com",
      "branding.reuters.com",
      "charts.data.reuters.com",
      "ci-fwc.pix.reuters.com",
      "ci-web.pix.reuters.com",
      "commsmonitor.wne.reuters.com",
      "contentdownloader.reuters.com",
      "coproducer.reuters.com",
      "datashare-black.data.reuters.com",
      "datashare-dev.data.reuters.com",
      "datashare-orange.data.reuters.com"
    ],
    "dangling": [
      "aws.dev.contentdownloader.reuters.com",
      "dev.ace.reuters.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=LMfrSuyToK_ofO0MSu-lf5QJhLYITHNDX09ofoF7_FY",
    "google-site-verification=FZwUpO_E2LIEPLqcxfWRpQipxi2faQ4Qt4wyYJpJr1g",
    "yahoo-verification-key=5bF6siWgzdkfub3ZLp8cnSL2ps44ipYuy28vgoM7qDA=",
    "google-site-verification=O1A9GoZ5a23atyZjR2IBMnmdG-jz3mrsQ900uMn0sbY",
    "openai-domain-verification=dv-3vP8oxOY9pDhfiwzHjba8jmZ"
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
      "aia_ocsp": null,
      "not_before": "20260903000000",
      "not_after": "20270320235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/finance/stocks/option",
      "/finance/stocks/financialHighlights",
      "/search",
      "/site-search/",
      "/beta",
      "/designtech",
      "/featured-optimize",
      "/energy-test",
      "/article/beta",
      "/sponsored/previewcampaign",
      "/sponsored/previewarticle",
      "/test/",
      "/news/archive/commentary",
      "/brandfeatures/venture-capital",
      "/assets/siteindex"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "westlawclassic.com.",
      "go.thomson.com.",
      "westlawjapan.com.",
      "seccurrents.com.",
      "thomsonreuters.com.",
      "netlinksolution.com.",
      "es.thomson.com.",
      "westlaw.com.tw.",
      "westlawprecision.com.au.",
      "westlawhub.com.",
      "caselines.com.",
      "westlawinternational.com.",
      "cyberrisk-insurer.com.",
      "thomsonreuters.co.kr.",
      "reuters.co.uk.",
      "corepublishingsolutions.com.",
      "westlawnextcanada.com.",
      "laleynextonline.com.ar.",
      "tr.com.",
      "incomesdata.co.uk.",
      "thomsonreuters.com.pe.",
      "checkpointworld.com.",
      "thomsonreuters.in.",
      "onesourcelogin.eu.",
      "westcheck.com.",
      "roundhall.ie.",
      "findprint.com.",
      "odentrack.com.",
      "ultratax.com.",
      "triform.com.",
      "hk-lawyer.org.",
      "gsionline.com.",
      "thomsonreuters.com.au.",
      "arbsearch.com.",
      "cvmailasia.com.",
      "thomsonreuters.es.",
      "pagerohbs.com.",
      "thomsonreuters.com.br.",
      "checkpointnz.co.nz.",
      "impotexpert.ca.",
      "trymateria.ai.",
      "parametric-insurer.com.",
      "ufile.ca.",
      "thomsonreuters.co.jp.",
      "gettaxnetpro.com.",
      "westlawtoday.com.",
      "reutersconnect.com.",
      "westlawasia.com.",
      "monitorsuite.com.",
      "fastsalestax.com.",
      "thomsonreutersmexico.com.",
      "findandprint.com.",
      "onesourcetax.com.",
      "informacionlegal.com.uy.",
      "personnet.com.",
      "cs.thomson.com.",
      "pubemplaw.net.",
      "archbolde-update.co.uk.",
      "oconnors.com.",
      "thomsonreuters.ca.",
      "onesourcelogin.com.au.",
      "westdoc.com.",
      "checkpointespana.es.",
      "reuters.fr.",
      "thomson.com.",
      "wbm-digital.com.",
      "cfslaw.com.",
      "westlawbusinesscurrents.com.",
      "sureprep.com.",
      "westlawchile.cl.",
      "sweetandmaxwell.co.uk.",
      "netlinksolutionqa.com.",
      "legalcurrent.com.",
      "iblj.com.",
      "es-insurer.com.",
      "ctracknotification.com.",
      "reuters.com.",
      "ctracknotification.ca.",
      "thomsonreuters.com.hk.",
      "thomsonreuters.co.nz.",
      "westlaw.co.nz.",
      "theinsurertv.com.",
      "reuters.it.",
      "carswell.com.",
      "rtonline.com.br.",
      "litigationmonitor.com.",
      "breakingviews.com.",
      "thomsonreuters.cn.",
      "editionsyvonblais.com.",
      "wl-w.com.",
      "mypay.thomson.com.",
      "reuters.de.",
      "westlawpro.com.",
      "checkpoint.cl.",
      "westfindandprint.com.",
      "livenotecentral.com.",
      "safeguard.co.nz.",
      "legalbusinessonline.com.",
      "westfindprint.com.",
      "westlawsolo.com.",
      "westlawrewards.com.",
      "checkpoint.com.pe.",
      "sustainable-insurer.com.",
      "westlawcourtexpress.com.",
      "laley.com.ar.",
      "revistadostribunais.com.br.",
      "consumerbankruptcynews.com.",
      "westlaw.com.",
      "legalexecutiveinstitute.com.",
      "westlawuk.com.",
      "securrents.com.",
      "thomsonreuters.com.my.",
      "program-manager.com.",
      "checkpointau.com.au.",
      "checkpointmexico.com.",
      "westlaw.com.au.",
      "consumerbankruptcynews.net.",
      "courtexpress.com.",
      "westmonitor.com.",
      "thomsonreuters.com.sg.",
      "serengetilaw.com.",
      "informacionlegalonline.com.uy.",
      "reuters.com.cn.",
      "informacionlegal.com.ar.",
      "theinsurer.com.",
      "lawtel.com.",
      "reuters.es.",
      "newwestlaw.com.",
      "taxnetproplus.com.",
      "odenpt.com.",
      "myroyalty.com.",
      "quickview.com.",
      "pubemplaw.com."
    ]
  },
  "elapsed_s": 29.5,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
