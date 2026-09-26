# Security Audit Report — feeds.feedburner.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://feeds.feedburner.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | feeds.feedburner.com |
| Test date | 2026-09-26 17:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 2, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 9 | info | SEC2 | security.txt published without a contact address | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ESF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ESF
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of feeds.feedburner.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 9. [INFO] security.txt published without a contact address (`SEC2`)

- **CWE:** CWE-1038
- **Detail:** /security.txt returns 200 but contains no mailto:/URL contact.
- **Recommendation:** Add a Contact: field per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "feeds.feedburner.com",
  "dns": {
    "a": [
      "64.233.189.118"
    ],
    "aaaa": [
      "2404:6800:4008:c07::76"
    ],
    "cname": "www4.l.google.com.",
    "mx": [],
    "ns": [],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=misc.google.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE2",
    "notBefore": "Sep 10 19:22:34 2026 GMT",
    "notAfter": "Dec  3 19:22:33 2026 GMT",
    "san": [
      "misc.google.com",
      "*.actions.google.com",
      "*.baseline.google.com",
      "*.developer.google.com",
      "*.developers.google.com",
      "*.ewoq.google.com",
      "*.arvr.google.com",
      "*.eu.aiapp.cloud.goog",
      "*.eu.aiapp.cloud-staging.goog",
      "*.eu.aiapp.cloud-test.goog",
      "*.firebase.google.com",
      "*.ggp.google.com",
      "*.global.aiapp.cloud.goog",
      "*.global.aiapp.cloud-staging.goog",
      "*.global.aiapp.cloud-test.goog",
      "*.personfinder.google.org",
      "*.quickoffice.com",
      "*.speech.google.com",
      "*.storage-nightly-test.googleusercontent.com",
      "*.storage-preprod-test-unified.googleusercontent.com",
      "*.storage-staging-test.googleusercontent.com",
      "*.storage-test-test.googleusercontent.com",
      "*.support.google.com",
      "*.us.aiapp.cloud.goog",
      "*.us.aiapp.cloud-staging.goog",
      "*.us.aiapp.cloud-test.goog",
      "*.widevine.com",
      "*.staging.widevine.com",
      "*.uat.widevine.com",
      "*.uat-nightly.widevine.com",
      "alphagenomedocs.com",
      "alphagenomecommunity.com",
      "adgoogle.net",
      "*.adgoogle.net",
      "admeld.com",
      "*.admeld.com",
      "advertisercommunity.com",
      "www.advertisercommunity.com",
      "advertiserscommunity.com",
      "*.advertiserscommunity.com",
      "adwords-community.com",
      "*.adwords-community.com",
      "adwordsexpress.com",
      "*.adwordsexpress.com",
      "angulardart.org",
      "*.angulardart.org",
      "appbridge.ca",
      "*.appbridge.ca",
      "appbridge.io",
      "*.appbridge.io",
      "appbridge.it",
      "*.appbridge.it",
      "apture.com",
      "*.apture.com",
      "atv-b2b-mgmt.goog",
      "*.atv-b2b-mgmt.goog",
      "beatthatquote.com",
      "*.beatthatquote.com",
      "blink.org",
      "*.blink.org",
      "brotli.org",
      "*.brotli.org",
      "bumpshare.com",
      "*.bumpshare.com",
      "bumptop.ca",
      "*.bumptop.ca",
      "bumptunes.com",
      "*.bumptunes.com",
      "bumptop.com",
      "*.bumptop.com",
      "bumptop.net",
      "*.bumptop.net",
      "bumptop.org",
      "*.bumptop.org",
      "campuslondon.com",
      "*.campuslondon.com",
      "certificate-transparency.org",
      "*.certificate-transparency.org",
      "chrome.com",
      "*.chrome.com",
      "chromecast.com",
      "*.chromecast.com",
      "chromium.org",
      "*.chromium.org",
      "*.issues.chromium.org",
      "clickserve.dartsearch.net",
      "clickserve.uk.dartsearch.net",
      "clickserve.eu.dartsearch.net",
      "clickserve.us2.dartsearch.net",
      "clickserver.googleads.com",
      "cloudburstresearch.com",
      "*.cloudburstresearch.com",
      "cloudfunctions.net",
      "*.cloudfunctions.net",
      "cloudrobotics.com",
      "*.cloudrobotics.com",
      "conscrypt.com",
      "*.conscrypt.com",
      "conscrypt.org",
      "*.conscrypt.org",
      "contentofferpilot.google",
      "contentpilot.google",
      "cookiechoices.org",
      "www.cookiechoices.org",
      "coova.com",
      "*.coova.com",
      "coova.net",
      "*.coova.net",
      "coova.org",
      "*.coova.org",
      "contactcenter.google",
      "*.contactcenter.google",
      "creatoracademy.youtube.com",
      "www.creatoracademy.youtube.com",
      "crr.com",
      "*.crr.com",
      "cs4hs.com",
      "*.cs4hs.com",
      "debug.com",
      "*.debug.com",
      "debugproject.com",
      "*.debugproject.com",
      "doodles.google",
      "*.doodles.google",
      "stxmosquitoproject.com",
      "*.stxmosquitoproject.com",
      "stxmosquitoproject.net",
      "*.stxmosquitoproject.net",
      "stxmosquitoproject.org",
      "*.stxmosquitoproject.org",
      "stcroixmosquitoproject.com",
      "*.stcroixmosquitoproject.com",
      "usvimosquitoproject.com",
      "*.usvimosquitoproject.com",
      "stxmosquito.com",
      "*.stxmosquito.com",
      "stcroixmosquito.com",
      "*.stcroixmosquito.com",
      "usvimosquito.com",
      "*.usvimosquito.com",
      "design.google",
      "*.design.google",
      "environment.google",
      "*.environment.google",
      "episodic.com",
      "*.episodic.com",
      "famebit.com",
      "*.famebit.com",
      "fbit.co",
      "*.fbit.co",
      "feedburner.com",
      "*.feedburner.com",
      "fflick.com",
      "*.fflick.com",
      "financeleadsonline.com",
      "*.financeleadsonline.com",
      "g-tun.com",
      "*.g-tun.com",
      "gbc.beatthatquote.com",
      "*.gbc.beatthatquote.com",
      "gerritcodereview.com",
      "*.gerritcodereview.com",
      "*.issues.gerritcodereview.com",
      "getbumptop.com",
      "*.getbumptop.com",
      "gipscorp.com",
      "*.gipscorp.com",
      "globaledu.org",
      "*.globaledu.org",
      "google.berlin",
      "*.google.berlin",
      "google.org",
      "*.google.org",
      "google.ventures",
      "*.google.ventures",
      "googleapps.com",
      "*.googleapps.com",
      "googlecompare.co.uk",
      "*.googlecompare.co.uk",
      "googledanmark.com",
      "*.googledanmark.com",
      "googlefinland.com",
      "*.googlefinland.com",
      "googlemaps.com",
      "*.googlemaps.com",
      "googlephotos.com",
      "*.googlephotos.com",
      "googleplay.com",
      "*.googleplay.com",
      "googleplus.com",
      "*.googleplus.com",
      "googlesverige.com",
      "*.googlesverige.com",
      "googletraveladservices.com",
      "*.googletraveladservices.com",
      "gridaware.app",
      "*.gridaware.app",
      "gsrc.io",
      "*.gsrc.io",
      "gsuite.com",
      "*.gsuite.com",
      "hdrplusdata.org",
      "*.hdrplusdata.org",
      "hindiweb.com",
      "*.hindiweb.com",
      "home-mqtt.goog",
      "*.home-mqtt.goog",
      "howtogetmo.co.uk",
      "*.howtogetmo.co.uk",
      "html5rocks.com",
      "*.html5rocks.com",
      "aiinfra.google",
      "*.aiinfra.google",
      "hwgo.com",
      "*.hwgo.com",
      "impermium.com",
      "*.impermium.com",
      "j2objc.org",
      "*.j2objc.org",
      "keytransparency.com",
      "*.keytransparency.com",
      "keytransparency.foo",
      "*.keytransparency.foo",
      "keytransparency.org",
      "*.keytransparency.org",
      "latentlogic.com",
      "*.latentlogic.com",
      "link.google",
      "*.link.google",
      "mdialog.com",
      "*.mdialog.com",
      "mfg-inspector.com",
      "*.mfg-inspector.com",
      "mobileview.page",
      "*.mobileview.page",
      "moodstocks.com",
      "*.moodstocks.com",
      "n339.asp-cc.com",
      "near.by",
      "*.near.by",
      "notebook.google",
      "*.notebook.google",
      "oauthz.com",
      "*.oauthz.com",
      "on.here",
      "*.on.here",
      "on2.com",
      "*.on2.com",
      "oneworldmanystories.com",
      "*.oneworldmanystories.com",
      "opal.goog",
      "*.opal.goog",
      "pagespeedmobilizer.com",
      "*.pagespeedmobilizer.com",
      "pageview.mobi",
      "*.pageview.mobi",
      "partylikeits1986.org",
      "*.partylikeits1986.org",
      "paxlicense.org",
      "*.paxlicense.org",
      "ping.feedburner.google.com",
      "pittpatt.com",
      "*.pittpatt.com",
      "polymerproject.org",
      "*.polymerproject.org",
      "populous.studio",
      "*.populous.studio",
      "postini.com",
      "*.postini.com",
      "questvisual.com",
      "*.questvisual.com",
      "quiksee.com",
      "*.quiksee.com",
      "quickshare.google",
      "*.quickshare.google",
      "quoteproxy.beatthatquote.com",
      "*.quoteproxy.beatthatquote.com",
      "raxium.com",
      "*.raxium.com",
      "recaptcha.net",
      "*.recaptcha.net",
      "revolv.com",
      "*.revolv.com",
      "ridepenguin.com",
      "*.ridepenguin.com",
      "rootmusic.bandpage.com",
      "www.bandpage.com",
      "s.svc-1.google.com",
      "*.s.svc-1.google.com",
      "sagetv.com",
      "*.sagetv.com",
      "saynow.com",
      "*.saynow.com",
      "schemer.com",
      "*.schemer.com",
      "screenwisetrends.com",
      "*.screenwisetrends.com",
      "screenwisetrendspanel.com",
      "*.screenwisetrendspanel.com",
      "searchplayground.google",
      "*.searchplayground.google",
      "stratozone.com",
      "*.stratozone.com",
      "suppliers.google",
      "*.suppliers.google",
      "rewards.google.com",
      "*.rewards.google.com",
      "snapseed.com",
      "*.snapseed.com",
      "solveforx.com",
      "*.solveforx.com",
      "sparkify.google",
      "*.sparkify.google",
      "synergyse.com",
      "*.synergyse.com",
      "thecleversense.com",
      "*.thecleversense.com",
      "thinkquarterly.co.uk",
      "*.thinkquarterly.co.uk",
      "thinkquarterly.com",
      "*.thinkquarterly.com",
      "txcloud.net",
      "*.txcloud.net",
      "txvia.com",
      "*.txvia.com",
      "useplannr.com",
      "*.useplannr.com",
      "v8project.org",
      "*.v8project.org",
      "velostrata.com",
      "*.velostrata.com",
      "videoreviewconsole.google",
      "*.videoreviewconsole.google",
      "virtual-app.com",
      "*.virtual-app.com",
      "virtualappdelivery.co",
      "*.virtualappdelivery.co",
      "virtualappdelivery.com",
      "*.virtualappdelivery.com",
      "virtualappdelivery.io",
      "*.virtualappdelivery.io",
      "virtualappdelivery.net",
      "*.virtualappdelivery.net",
      "virtualappdelivery.org",
      "*.virtualappdelivery.org",
      "wallet.com",
      "*.wallet.com",
      "waze.com",
      "*.waze.com",
      "webappfieldguide.com",
      "*.webappfieldguide.com",
      "webgpu.dev",
      "*.webgpu.dev",
      "webgpu.io",
      "*.webgpu.io",
      "weltweitwachsen.de",
      "www.weltweitwachsen.de",
      "whatbrowser.org",
      "*.whatbrowser.org",
      "womenwill.com",
      "*.womenwill.com",
      "womenwill.id",
      "*.womenwill.id",
      "womenwill.in",
      "*.womenwill.in",
      "womenwill.com.br",
      "*.womenwill.com.br",
      "womenwill.mx",
      "*.womenwill.mx",
      "workbenchplatform.com",
      "*.workbenchplatform.com",
      "workbencheducation.com",
      "*.workbencheducation.com",
      "workbencheducation.net",
      "*.workbencheducation.net",
      "wrkbnch.io",
      "*.wrkbnch.io",
      "word-lens.com",
      "*.word-lens.com",
      "wordlens.com",
      "*.wordlens.com",
      "wordlens.net",
      "*.wordlens.net",
      "x.company",
      "*.x.company",
      "x.team",
      "*.x.team",
      "xviaduct.app",
      "*.xviaduct.app",
      "youtubemobilesupport.com",
      "*.youtubemobilesupport.com",
      "zukunftswerkstatt.de",
      "www.zukunftswerkstatt.de",
      "*.northamerica.apigee.google.com",
      "*.apigee.google.com",
      "accounts.mandiant.com",
      "*.looker-staging.chronicle.security",
      "autodatatoolkit.google",
      "*.autodatatoolkit.google",
      "devicecenter.google",
      "*.devicecenter.google",
      "mmmdata.google",
      "*.mmmdata.google",
      "sbx-internal.dev",
      "*.sbx-internal.dev",
      "cloud-hardware-customer-connect.google"
    ],
    "days_left": 68,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "64.233.189.118",
    "open": []
  },
  "https": {
    "status": 404,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: ESF"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.feeds.feedburner.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 404
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 200,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 200
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "cname_chain": [
    "www4.l.google.com"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null
    }
  },
  "elapsed_s": 7.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
