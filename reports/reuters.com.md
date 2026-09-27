# Security Audit Report — reuters.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://reuters.com/ |
| Bug bounty program | Reuters |
| Listed scope domain | reuters.com |
| Test date | 2026-09-27 00:30 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 6, Info: 16)

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
| 15 | low | RED10 | Host header reflected into redirect Location | CWE-601 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 20 | info | H22 | Server answers with HTTP/1.0 | CWE-319 |
| 21 | info | CT1 | 138 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 22 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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
- **Detail:** Apex TXT records with verification/token content: yahoo-verification-key=5bF6siWgzdkfub3ZLp8cnSL2ps44ipYuy28vgoM7qDA=; facebook-domain-verification=ra7bjxso3pnjy2p63mdc0002chquca; apple-domain-verification=voAz1fDhqIN4vRxG52m4VSOgLipH0OMyfJIprobVB1U
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [LOW] Host header reflected into redirect Location (`RED10`)

- **CWE:** CWE-601
- **Detail:** GET with Host: evil-auditor.example -> Location: https://www.evil-auditor.example/
- **Recommendation:** Validate redirect targets against the expected host.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 28 disallow path(s), e.g. /finance/stocks/option, /finance/stocks/financialHighlights, /search, /site-search/, /beta
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 155.46.172.255 carries PTR thomsonreuters.es., westlawuk.com., pagerohbs.com., myroyalty.com., westlawtoday.com., thomsonreuters.co.jp., cs.thomson.com., program-manager.com., lawtel.com., westfindprint.com., thomsonreuters.com.my., westlaw.com.tw., thomsonreuters.ca., checkpoint.cl., reuters.co.uk., onesourcelogin.com.au., onesourcelogin.eu., thomsonreuters.in., archbolde-update.co.uk., westlawhub.com., westlawjapan.com., checkpoint.com.pe., informacionlegal.com.uy., seccurrents.com., hk-lawyer.org., thomsonreuters.co.nz., informacionlegalonline.com.uy., reutersconnect.com., ultratax.com., legalexecutiveinstitute.com., iblj.com., pubemplaw.com., onesourcetax.com., thomsonreuters.com.pe., carswell.com., laley.com.ar., reuters.it., westmonitor.com., westlawprecision.com.au., westlawnextcanada.com., westlawclassic.com., theinsurer.com., legalcurrent.com., incomesdata.co.uk., checkpointworld.com., caselines.com., ctracknotification.ca., westlawasia.com., monitorsuite.com., westlaw.com.au., checkpointmexico.com., triform.com., safeguard.co.nz., checkpointnz.co.nz., corepublishingsolutions.com., westlawchile.cl., breakingviews.com., gsionline.com., westlawrewards.com., westlawbusinesscurrents.com., livenotecentral.com., wbm-digital.com., ctracknotification.com., odentrack.com., revistadostribunais.com.br., thomsonreuters.com.au., sweetandmaxwell.co.uk., tr.com., thomsonreutersmexico.com., securrents.com., reuters.es., netlinksolutionqa.com., thomson.com., westlawcourtexpress.com., netlinksolution.com., newwestlaw.com., rtonline.com.br., reuters.com., reuters.com.cn., parametric-insurer.com., courtexpress.com., westlaw.com., taxnetproplus.com., wl-w.com., westlaw.co.nz., arbsearch.com., editionsyvonblais.com., litigationmonitor.com., es.thomson.com., cvmailasia.com., serengetilaw.com., cfslaw.com., thomsonreuters.com.hk., westlawpro.com., findandprint.com., es-insurer.com., reuters.de., thomsonreuters.cn., pubemplaw.net., impotexpert.ca., odenpt.com., westfindandprint.com., checkpointau.com.au., thomsonreuters.com., westcheck.com., laleynextonline.com.ar., westlawsolo.com., consumerbankruptcynews.net., gettaxnetpro.com., oconnors.com., trymateria.ai., westlawinternational.com., legalbusinessonline.com., personnet.com., mypay.thomson.com., thomsonreuters.co.kr., ufile.ca., cyberrisk-insurer.com., quickview.com., reuters.fr., sureprep.com., thomsonreuters.com.sg., findprint.com., go.thomson.com., checkpointespana.es., fastsalestax.com., roundhall.ie., theinsurertv.com., consumerbankruptcynews.com., informacionlegal.com.ar., westdoc.com., thomsonreuters.com.br., sustainable-insurer.com. for reuters.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for reuters.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The reuters.com certificate lists an AIA OCSP responder (http://ocsp.sectigo.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 20. [INFO] Server answers with HTTP/1.0 (`H22`)

- **CWE:** CWE-319
- **Detail:** The root response of reuters.com uses HTTP/1.0, the oldest version still in use; modern sites should serve HTTP/1.1 or 2.
- **Recommendation:** Serve HTTP/1.1 or HTTP/2 from the edge.

### 21. [INFO] 138 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: apps.data.reuters.com, aws.contentdownloader.reuters.com, aws.dev.contentdownloader.reuters.com, aws.qa.contentdownloader.reuters.com, dev.ace.reuters.com, dev.commsmonitor.wne.reuters.com, dev.contentdownloader.reuters.com, dev.gpdb.media.reuters.com, dev.gpdbservices.media.reuters.com, dev.graphics.reuters.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 22. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

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
      "mxa-00160c04.gslb.pphosted.com (pref 10)",
      "mxb-00160c04.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-aws-1.thomsonreuters.com.",
      "ns-aws-4.thomsonreuters.co.uk.",
      "ns-aws-3.thomsonreuters.org.",
      "ns-aws-2.thomsonreuters.net."
    ],
    "caa": [],
    "spf": [
      "yahoo-verification-key=5bF6siWgzdkfub3ZLp8cnSL2ps44ipYuy28vgoM7qDA=",
      "facebook-domain-verification=ra7bjxso3pnjy2p63mdc0002chquca",
      "apple-domain-verification=voAz1fDhqIN4vRxG52m4VSOgLipH0OMyfJIprobVB1U",
      "openai-domain-verification=dv-3vP8oxOY9pDhfiwzHjba8jmZ",
      "google-site-verification=O1A9GoZ5a23atyZjR2IBMnmdG-jz3mrsQ900uMn0sbY",
      "google-site-verification=LMfrSuyToK_ofO0MSu-lf5QJhLYITHNDX09ofoF7_FY",
      "google-site-verification=7UwjlMmBYuyFWx01Pu6NEVEWRPD9W25PnwffZejseEg",
      "apple-domain-verification=cKpm3aVB5VEf9fQ0oxIIumulcv3CvTjrOGvqF8nUDO8",
      "google-site-verification=FZwUpO_E2LIEPLqcxfWRpQipxi2faQ4Qt4wyYJpJr1g",
      "MS=ms24417066",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all"
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
    "days_left": 174,
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
    "yahoo-verification-key=5bF6siWgzdkfub3ZLp8cnSL2ps44ipYuy28vgoM7qDA=",
    "facebook-domain-verification=ra7bjxso3pnjy2p63mdc0002chquca",
    "apple-domain-verification=voAz1fDhqIN4vRxG52m4VSOgLipH0OMyfJIprobVB1U",
    "openai-domain-verification=dv-3vP8oxOY9pDhfiwzHjba8jmZ",
    "google-site-verification=O1A9GoZ5a23atyZjR2IBMnmdG-jz3mrsQ900uMn0sbY"
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
      "aia_ocsp": "http://ocsp.sectigo.com",
      "serial": 112124235717666899219800201050181430418,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.sectigo.com/SectigoPublicServerAuthenticationCAOVR40.crl"
      ],
      "subject_dn": "310b30090603550406130243413110300e060355040813074f6e746172696f31243022060355040a131b54686f6d736f6e205265757465727320436f72706f726174696f6e311b30190603550403131274686f6d736f6e726575746572732e636f6d",
      "issuer_dn": "310b300906035504061302474231183016060355040a130f5365637469676f204c696d69746564313730350603550403132e5365637469676f205075626c6963205365727665722041757468656e7469636174696f6e204341204f5620523430",
      "not_before": "20260903000000",
      "not_after": "20270320235959"
    },
    "ocsp": "explicit-status"
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
      "thomsonreuters.es.",
      "westlawuk.com.",
      "pagerohbs.com.",
      "myroyalty.com.",
      "westlawtoday.com.",
      "thomsonreuters.co.jp.",
      "cs.thomson.com.",
      "program-manager.com.",
      "lawtel.com.",
      "westfindprint.com.",
      "thomsonreuters.com.my.",
      "westlaw.com.tw.",
      "thomsonreuters.ca.",
      "checkpoint.cl.",
      "reuters.co.uk.",
      "onesourcelogin.com.au.",
      "onesourcelogin.eu.",
      "thomsonreuters.in.",
      "archbolde-update.co.uk.",
      "westlawhub.com.",
      "westlawjapan.com.",
      "checkpoint.com.pe.",
      "informacionlegal.com.uy.",
      "seccurrents.com.",
      "hk-lawyer.org.",
      "thomsonreuters.co.nz.",
      "informacionlegalonline.com.uy.",
      "reutersconnect.com.",
      "ultratax.com.",
      "legalexecutiveinstitute.com.",
      "iblj.com.",
      "pubemplaw.com.",
      "onesourcetax.com.",
      "thomsonreuters.com.pe.",
      "carswell.com.",
      "laley.com.ar.",
      "reuters.it.",
      "westmonitor.com.",
      "westlawprecision.com.au.",
      "westlawnextcanada.com.",
      "westlawclassic.com.",
      "theinsurer.com.",
      "legalcurrent.com.",
      "incomesdata.co.uk.",
      "checkpointworld.com.",
      "caselines.com.",
      "ctracknotification.ca.",
      "westlawasia.com.",
      "monitorsuite.com.",
      "westlaw.com.au.",
      "checkpointmexico.com.",
      "triform.com.",
      "safeguard.co.nz.",
      "checkpointnz.co.nz.",
      "corepublishingsolutions.com.",
      "westlawchile.cl.",
      "breakingviews.com.",
      "gsionline.com.",
      "westlawrewards.com.",
      "westlawbusinesscurrents.com.",
      "livenotecentral.com.",
      "wbm-digital.com.",
      "ctracknotification.com.",
      "odentrack.com.",
      "revistadostribunais.com.br.",
      "thomsonreuters.com.au.",
      "sweetandmaxwell.co.uk.",
      "tr.com.",
      "thomsonreutersmexico.com.",
      "securrents.com.",
      "reuters.es.",
      "netlinksolutionqa.com.",
      "thomson.com.",
      "westlawcourtexpress.com.",
      "netlinksolution.com.",
      "newwestlaw.com.",
      "rtonline.com.br.",
      "reuters.com.",
      "reuters.com.cn.",
      "parametric-insurer.com.",
      "courtexpress.com.",
      "westlaw.com.",
      "taxnetproplus.com.",
      "wl-w.com.",
      "westlaw.co.nz.",
      "arbsearch.com.",
      "editionsyvonblais.com.",
      "litigationmonitor.com.",
      "es.thomson.com.",
      "cvmailasia.com.",
      "serengetilaw.com.",
      "cfslaw.com.",
      "thomsonreuters.com.hk.",
      "westlawpro.com.",
      "findandprint.com.",
      "es-insurer.com.",
      "reuters.de.",
      "thomsonreuters.cn.",
      "pubemplaw.net.",
      "impotexpert.ca.",
      "odenpt.com.",
      "westfindandprint.com.",
      "checkpointau.com.au.",
      "thomsonreuters.com.",
      "westcheck.com.",
      "laleynextonline.com.ar.",
      "westlawsolo.com.",
      "consumerbankruptcynews.net.",
      "gettaxnetpro.com.",
      "oconnors.com.",
      "trymateria.ai.",
      "westlawinternational.com.",
      "legalbusinessonline.com.",
      "personnet.com.",
      "mypay.thomson.com.",
      "thomsonreuters.co.kr.",
      "ufile.ca.",
      "cyberrisk-insurer.com.",
      "quickview.com.",
      "reuters.fr.",
      "sureprep.com.",
      "thomsonreuters.com.sg.",
      "findprint.com.",
      "go.thomson.com.",
      "checkpointespana.es.",
      "fastsalestax.com.",
      "roundhall.ie.",
      "theinsurertv.com.",
      "consumerbankruptcynews.com.",
      "informacionlegal.com.ar.",
      "westdoc.com.",
      "thomsonreuters.com.br.",
      "sustainable-insurer.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.reuters.com/",
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
    "crl": {
      "url": "http://crl.sectigo.com/SectigoPublicServerAuthenticationCAOVR40.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "cipher_ver": "TLSv1.2",
    "root_status": 301
  },
  "elapsed_s": 44.2,
  "rechecked": "2026-09-27 00:08 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- re-run #15 passive additions: TLS 1.0/1.1, cipher-suite and key-exchange observations come from the handshake the base TLS check already performed plus one quiet re-handshake with no HTTP traffic; HTML-level angles read the root document already fetched for header checks; the only extra request this pass is a read-only GET to /.well-known/openid-configuration (plus the earlier passes' security.txt, sitemap.xml and CRL GETs).
- Findings are reported against the public program scope; submission through the program tracker is pending.
