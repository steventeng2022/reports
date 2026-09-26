# Security Audit Report — photos.app.goo.gl

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://photos.app.goo.gl/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | photos.app.goo.gl |
| Test date | 2026-09-26 18:57 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 9 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 10 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 11 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 12 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

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

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ESF
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (67esg27wjdjil6.photos.app.goo.gl and gh3w1nyn9wrz5w.photos.app.goo.gl) both resolve to distinct addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 9. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of photos.app.goo.gl has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 10. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of photos.app.goo.gl permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 11. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of photos.app.goo.gl includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 12. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 142.250.196.206 carries PTR nctsaa-ac-in-f14.1e100.net. for photos.app.goo.gl.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "photos.app.goo.gl",
  "dns": {
    "a": [
      "142.250.196.206"
    ],
    "aaaa": [
      "2404:6800:4012:6::200e"
    ],
    "cname": null,
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
    "subject": "commonName=misc-sni.google.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR2",
    "notBefore": "Sep 10 19:22:23 2026 GMT",
    "notAfter": "Dec  3 19:22:22 2026 GMT",
    "san": [
      "misc-sni.google.com",
      "*.aiplatform-notebook.cloud.google.com",
      "*.aiplatform-training.cloud.google.com",
      "*.backupdr.cloud.google.com",
      "*.backupdr.cloud.google",
      "*.backupdr-staging.cloud.google.com",
      "*.backupdr-staging.cloud.google",
      "*.backupdr-autopush.cloud.google.com",
      "*.backupdr-autopush.cloud.google",
      "*.backupdr-dev.cloud.google.com",
      "*.backupdr-dev.cloud.google",
      "*.backupdr-sandbox.cloud.google.com",
      "*.backupdr-sandbox.cloud.google",
      "*.brocaproject.com",
      "brocaproject.com",
      "*.composer.cloud.google.com",
      "*.composer.cloud.google",
      "*.composer-staging.cloud.google.com",
      "*.composer-staging.cloud.google",
      "*.composer-qa.cloud.google.com",
      "*.composer-qa.cloud.google",
      "*.composer-dev.cloud.google.com",
      "*.composer-dev.cloud.google",
      "*.datalab.cloud.google.com",
      "*.datafusion.cloud.google.com",
      "*.datafusion.cloud.google",
      "*.datafusion-staging.cloud.google.com",
      "*.datafusion-staging.cloud.google",
      "*.datafusion-dev.cloud.google.com",
      "*.datafusion-dev.cloud.google",
      "*.datafusion-api.cloud.google.com",
      "*.datafusion-api.cloud.google",
      "*.datafusion-api-staging.cloud.google.com",
      "*.datafusion-api-staging.cloud.google",
      "*.datafusion-api-dev.cloud.google.com",
      "*.datafusion-api-dev.cloud.google",
      "*.dataplex.cloud.google.com",
      "*.dataplex-staging.cloud.google.com",
      "*.dataplex-dev.cloud.google.com",
      "*.dataproc.cloud.google.com",
      "*.dataproc.cloud.google",
      "*.dataproc-image-staging.cloud.google.com",
      "*.dataproc-image-staging.cloud.google",
      "*.dataproc-staging.cloud.google.com",
      "*.dataproc-staging.cloud.google",
      "*.dataproc-test.cloud.google.com",
      "*.dataproc-test.cloud.google",
      "*.earthengine.google.co.in",
      "*.earthengine.google.com",
      "*.fiber.google.com",
      "*.gateway.dev",
      "*.de.gateway.dev",
      "*.ew.gateway.dev",
      "*.uc.gateway.dev",
      "*.asia-east1.gateway.dev",
      "*.europe-west1.gateway.dev",
      "*.us-central1.gateway.dev",
      "*.global.accountverification.cloud.google",
      "*.staging-global.accountverification.cloud.google",
      "*.autopush-global.accountverification.cloud.google",
      "*.google-syndication.com",
      "*.dev.google-syndication.com",
      "*.staging.google-syndication.com",
      "*.googleacquisitionmigration.com",
      "*.gvt5.com",
      "*.healthcare.cloud.google.com",
      "*.machinelearningtools.cloud.google.com",
      "*.machinelearningtools-staging.cloud.google.com",
      "*.machinelearningtools-autopush.cloud.google.com",
      "*.machinelearningtools-dev.cloud.google.com",
      "*.mapmaker.google.com",
      "*.microhost.google.com",
      "*.notebooks.cloud.google.com",
      "*.notebooks.cloud.google",
      "*.picnik.com",
      "picnik.com",
      "*.pipelines.cloud.google.com",
      "*.podcasts.goog",
      "*.tensorboard.cloud.google.com",
      "*.tensorboard-autopush.cloud.google.com",
      "*.tensorboard-dev.cloud.google.com",
      "*.tensorboard-staging.cloud.google.com",
      "*.tensorboard-test.cloud.google.com",
      "*.vast.cloud.google.com",
      "*.vast-staging.cloud.google.com",
      "*.vast-autopush.cloud.google.com",
      "*.vast-sandbox.cloud.google.com",
      "abc.xyz",
      "*.abc.xyz",
      "adsense.com",
      "www.adsense.com",
      "adsensecustomsearchads.com",
      "*.adsensecustomsearchads.com",
      "adsenseformobileapps.com",
      "advertisercommunity.com",
      "*.advertisercommunity.com",
      "cloudyoryx.dev",
      "*.cloudyoryx.dev",
      "eageroryx.dev",
      "*.eageroryx.dev",
      "stage.advertisercommunity.com",
      "*.stage.advertisercommunity.com",
      "de.advertisercommunity.com",
      "*.de.advertisercommunity.com",
      "en.advertisercommunity.com",
      "*.en.advertisercommunity.com",
      "es.advertisercommunity.com",
      "*.es.advertisercommunity.com",
      "fr.advertisercommunity.com",
      "*.fr.advertisercommunity.com",
      "id.advertisercommunity.com",
      "*.id.advertisercommunity.com",
      "it.advertisercommunity.com",
      "*.it.advertisercommunity.com",
      "ja.advertisercommunity.com",
      "*.ja.advertisercommunity.com",
      "pl.advertisercommunity.com",
      "*.pl.advertisercommunity.com",
      "pt.advertisercommunity.com",
      "*.pt.advertisercommunity.com",
      "ru.advertisercommunity.com",
      "*.ru.advertisercommunity.com",
      "th.advertisercommunity.com",
      "*.th.advertisercommunity.com",
      "vi.advertisercommunity.com",
      "*.vi.advertisercommunity.com",
      "zh.advertisercommunity.com",
      "*.zh.advertisercommunity.com",
      "ampcache.com",
      "*.ampcache.com",
      "ampproject.com",
      "*.ampproject.com",
      "ampproject.net",
      "*.ampproject.net",
      "*.recaptcha.ampproject.net",
      "ampproject.org",
      "*.ampproject.org",
      "*.cdn.ampproject.org",
      "androidify.com",
      "*.androidify.com",
      "app.goo.gl",
      "*.app.goo.gl",
      "channel-app.google",
      "console.au.cloud.google",
      "*.au.cloud.google",
      "console.ca.cloud.google",
      "*.ca.cloud.google",
      "console.eu.cloud.google",
      "*.eu.cloud.google",
      "console.eu.cloud.google.com",
      "console.il.cloud.google",
      "*.il.cloud.google",
      "console.in.cloud.google",
      "*.in.cloud.google",
      "console.it.cloud.google",
      "*.it.cloud.google",
      "console.jp.cloud.google",
      "*.jp.cloud.google",
      "console.sa.cloud.google",
      "*.sa.cloud.google",
      "console.uk.cloud.google",
      "*.uk.cloud.google",
      "console.us.cloud.google",
      "*.us.cloud.google",
      "cloud.google",
      "*.cloud.google",
      "colab.research.google.com",
      "code.webrtc.org",
      "bugs.webrtc.org",
      "issues.webrtc.org",
      "*.issues.webrtc.org",
      "chronicle.security",
      "*.chronicle.security",
      "*.backstory.chronicle.security",
      "*.backstory-staging.chronicle.security",
      "chronicleforgood.com",
      "*.chronicleforgood.com",
      "looker.chronicle.security",
      "*.looker.chronicle.security",
      "looker-staging.chronicle.security",
      "*.looker-staging.chronicle.security",
      "chroniclesec.com",
      "*.chroniclesec.com",
      "*.backstory.chroniclesec.com",
      "crossmediapanel.com",
      "*.crossmediapanel.com",
      "crowdcalling.google",
      "dataliberation.org",
      "*.dataliberation.org",
      "datasetsearch.research.google.com",
      "dg-meta.video.google.com",
      "digitalassetlinks.org",
      "*.digitalassetlinks.org",
      "discover.google.com",
      "*.discover.google.com",
      "domains.google",
      "*.domains.google",
      "earlydays.google",
      "*.earlydays.google",
      "engineering.google",
      "*.engineering.google",
      "fastlane.ci",
      "firebase.new",
      "www.firebase.new",
      "floonet.goog",
      "*.floonet.goog",
      "gapi.waze.com",
      "gmbads.gle",
      "*.gmbads.gle",
      "go-lang.com",
      "*.go-lang.com",
      "go-lang.net",
      "*.go-lang.net",
      "go-lang.org",
      "*.go-lang.org",
      "golang.com",
      "*.golang.com",
      "golang.net",
      "*.golang.net",
      "golang.org",
      "*.golang.org",
      "golang.google.cn",
      "*.golang.google.cn",
      "googleblog.com",
      "*.googleblog.com",
      "googlecert.net",
      "*.googlecert.net",
      "googlestore.com",
      "www.googlestore.com",
      "grow.google",
      "*.grow.google",
      "g.dev",
      "*.g.dev",
      "g.page",
      "*.g.page",
      "hey.gle",
      "*.hey.gle",
      "ok.gle",
      "*.ok.gle",
      "hats.goog",
      "*.hats.goog",
      "iamremarkable.org",
      "www.iamremarkable.org",
      "identityplatform.google",
      "*.identityplatform.google",
      "*.global.identityplatform.google",
      "*.staging-global.identityplatform.google",
      "*.staging-qual-global.identityplatform.google",
      "*.autopush-global.identityplatform.google",
      "*.autopush-qual-global.identityplatform.google",
      "lanternal.com",
      "*.lanternal.com",
      "lers.google",
      "nel.goog",
      "*.nel.goog",
      "nomulus.foo",
      "*.nomulus.foo",
      "notebooklm.google",
      "ordering.page",
      "*.ordering.page",
      "macservice.goog",
      "*.macservice.goog",
      "makersuite.google",
      "*.makersuite.google",
      "pagespeed.web.dev",
      "payment.goog",
      "*.payment.goog",
      "picasaweb.com",
      "*.picasaweb.com",
      "picasaweb.net",
      "*.picasaweb.net",
      "picasaweb.org",
      "*.picasaweb.org",
      "pixate.com",
      "www.pixate.com",
      "pki.goog",
      "*.pki.goog",
      "play.space",
      "*.play.space",
      "privacysandbox.google.com",
      "*.privacysandbox.google.com",
      "projectgomie.google",
      "*.projectgomie.google",
      "qr.google",
      "*.qr.google",
      "rbm.goog",
      "*.rbm.goog",
      "registry-qa.google",
      "www.registry-qa.google",
      "registry-sandbox.google",
      "www.registry-sandbox.google",
      "registry.google",
      "www.registry.google",
      "research.youtube",
      "*.research.youtube",
      "savethedate.foo",
      "*.savethedate.foo",
      "songwriters.youtube",
      "*.songwriters.youtube",
      "source.bazel.build",
      "*.source.bazel.build",
      "support.registry-qa.google",
      "support.registry-sandbox.google",
      "support.registry.google",
      "sprayscape.com",
      "www.sprayscape.com",
      "tfhub.dev",
      "*.tfhub.dev",
      "thegooglestore.com",
      "www.thegooglestore.com",
      "tiltbrush.com",
      "*.tiltbrush.com",
      "travel.google",
      "*.travel.google",
      "webmproject.org",
      "*.webmproject.org",
      "issues.webmproject.org",
      "*.issues.webmproject.org",
      "webpkgcache.com",
      "*.webpkgcache.com",
      "workinxr.dev",
      "*.workinxr.dev",
      "xplr.co",
      "*.xplr.co",
      "zynamics.com",
      "*.zynamics.com",
      "app-ads-services.com",
      "*.app-ads-services.com"
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
    "ip": "142.250.196.206",
    "open": []
  },
  "https": {
    "status": 400,
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
      "origin": "https://sub.photos.app.goo.gl",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://photos.app.goo.gl/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 400,
    "/sitemap.xml": 400,
    "/.well-known/security.txt": 400,
    "/security.txt": 400,
    "/.git/HEAD": 400,
    "/.git/config": 400,
    "/.env": 400,
    "/.htaccess": 400,
    "/wp-login.php": 400,
    "/phpmyadmin/index.php": 400,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 0,
    "notable": [],
    "sample": []
  },
  "wildcard_dns": true,
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
      "not_before": "20260910192223",
      "not_after": "20261203192222"
    }
  },
  "x12": {
    "status": 400,
    "ptr": [
      "nctsaa-ac-in-f14.1e100.net."
    ]
  },
  "elapsed_s": 19.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
