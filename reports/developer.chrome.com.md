# Security Audit Report — developer.chrome.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://developer.chrome.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | developer.chrome.com |
| Test date | 2026-09-27 01:16 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 1, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 12 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 13 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 15 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 16 | info | HTML7 | Insecure http:// references inside an HTTPS document | CWE-319 |
| 17 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 18 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 19 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 20 | info | HTML12 | preconnect/dns-prefetch declares third-party destinations | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Google Frontend
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Google Frontend
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=kzYPT3ILdlLt0WQHyNQ9kRNFP0iNjwNAZ96TCBcD1Hs
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of developer.chrome.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1 disallow path(s), e.g. Sitemap:
- **Recommendation:** Review disallowed paths; robots is not access control.

### 12. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of developer.chrome.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 13. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of developer.chrome.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 142.250.204.46 carries PTR hkg07s38-in-f14.1e100.net., lctsaa-ac-in-f14.1e100.net. for developer.chrome.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 15. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on developer.chrome.com lists 3 <loc> URL(s) across 4 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 16. [INFO] Insecure http:// references inside an HTTPS document (`HTML7`)

- **CWE:** CWE-319
- **Detail:** Root document of developer.chrome.com references 3 distinct http:// URL(s) (e.g. http://schema.org, http://schema.org/, http://www.w3.org/2000/svg); using them drops to unencrypted transport.
- **Recommendation:** Use https:// references or relative URLs.

### 17. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of developer.chrome.com references 13 distinct third-party registrable domains (e.g. google.cn, web.dev, gstatic.com, googleapis.com, google.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 18. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of developer.chrome.com sends a CSP but contains 6 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 19. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of developer.chrome.com carries alt-svc h3=":443"; ma=2592000,h3-29=":443"; ma=2592000; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 20. [INFO] preconnect/dns-prefetch declares third-party destinations (`HTML12`)

- **CWE:** CWE-200
- **Detail:** Root document of developer.chrome.com declares preconnect/dns-prefetch/modulepreload for 3 third-party registrable domain(s) (e.g. google-analytics.com, googleapis.com, gstatic.com); declared (not yet loaded) destinations widen the expected network topology of the page.
- **Recommendation:** Review declared third-party destinations as part of the supply-chain inventory.

## Evidence (raw response observations)

```json
{
  "domain": "developer.chrome.com",
  "dns": {
    "a": [
      "142.250.204.46"
    ],
    "aaaa": [
      "2404:6800:4012:9::200e"
    ],
    "cname": null,
    "mx": [],
    "ns": [],
    "caa": [],
    "spf": [
      "google-site-verification=kzYPT3ILdlLt0WQHyNQ9kRNFP0iNjwNAZ96TCBcD1Hs"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=misc.google.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR2",
    "notBefore": "Sep 10 19:22:23 2026 GMT",
    "notAfter": "Dec  3 19:22:22 2026 GMT",
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
    "days_left": 67,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "142.250.204.46",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Chrome for Developers"
  },
  "mixed_content": [],
  "tech": [
    "Server: Google Frontend"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.developer.chrome.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://developer.chrome.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 0,
    "notable": [],
    "sample": []
  },
  "apex_txt": [
    "google-site-verification=kzYPT3ILdlLt0WQHyNQ9kRNFP0iNjwNAZ96TCBcD1Hs"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "serial": 83939359658809846028182493360257526588,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/wr2/oBFYYahzgVI.crl"
      ],
      "subject_dn": "311830160603550403130f6d6973632e676f6f676c652e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303575232",
      "not_before": "20260910192223",
      "not_after": "20261203192222"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "Sitemap:"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "hkg07s38-in-f14.1e100.net.",
      "lctsaa-ac-in-f14.1e100.net."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=63072000; includeSubdomains; preload",
    "sitemap": {
      "urls": 3,
      "indexes": 4
    },
    "crl": {
      "url": "http://c.pki.goog/wr2/oBFYYahzgVI.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "x16": {
    "root_status": 200,
    "alt_svc": "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000",
    "preconnect": [
      "google-analytics.com",
      "googleapis.com",
      "gstatic.com"
    ]
  },
  "elapsed_s": 20.8,
  "rechecked": "2026-09-27 01:08 UTC"
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
- re-run #16 passive additions: the edge/protocol angles read the alt-svc, server-timing and CDN-identification headers from the one root GET; the preconnect/dns-prefetch, base-href and noindex angles parse the already-fetched root document; the TLS 1.2-only ceiling, SHA-1 signature and weak-key angles use the certificate evidence the base TLS check already captured; the only extra requests this pass are two read-only GETs (/.well-known/jwks.json and /.well-known/change-password).
- Findings are reported against the public program scope; submission through the program tracker is pending.
