# Security Audit Report — g.page

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://g.page/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | g.page |
| Test date | 2026-09-27 00:19 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 5, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 9 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 12 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 13 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 14 | low | RD2 | HTTPS root redirects to a different domain | CWE-200 |
| 15 | low | H21 | HSTS does not cover subdomains | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ESF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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

### 8. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 9. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (tmhs8scspg1f13.g.page and ejhofgw6gl0km8.g.page) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of g.page has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of g.page permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 12. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of g.page includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 13. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 216.239.32.27 carries PTR any-in-201b.1e100.net. for g.page.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 14. [LOW] HTTPS root redirects to a different domain (`RD2`)

- **CWE:** CWE-200
- **Detail:** https://g.page/ answered 302 with Location: https://business.google.com (cross-domain handoff at the entry point).
- **Recommendation:** Review the cross-domain redirect; it discloses the real entry point and can be abused in open-redirect-style flows.

### 15. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on g.page has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of g.page.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

## Evidence (raw response observations)

```json
{
  "domain": "g.page",
  "dns": {
    "a": [
      "216.239.32.27"
    ],
    "aaaa": [
      "2001:4860:4802:32::1b"
    ],
    "cname": null,
    "mx": [],
    "ns": [
      "ns2.zdns.google.",
      "ns3.zdns.google.",
      "ns1.zdns.google.",
      "ns4.zdns.google."
    ],
    "caa": [
      "0 issue \"pki.goog\""
    ],
    "spf": [
      "v=spf1 ?all"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:mailauth-reports@google.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=misc-sni.google.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE2",
    "notBefore": "Sep 10 19:22:34 2026 GMT",
    "notAfter": "Dec  3 19:22:33 2026 GMT",
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
    "ip": "216.239.32.27",
    "open": []
  },
  "https": {
    "status": 302,
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
      "origin": "https://sub.g.page",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://g.page/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 404,
    "/security.txt": 302,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 404,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "serial": 277117696272052674691383779427389564511,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/we2/xuzt3PU9F_w.crl"
      ],
      "subject_dn": "311c301a060355040313136d6973632d736e692e676f6f676c652e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574532",
      "not_before": "20260910192234",
      "not_after": "20261203192233"
    }
  },
  "http2": {
    "hsts_preloaded": true
  },
  "x12": {
    "status": 302,
    "ptr": [
      "any-in-201b.1e100.net."
    ]
  },
  "x13": {
    "root_status": 302,
    "root_location": "https://business.google.com",
    "http_status": 301,
    "p404_status": 302,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 302,
    "hsts": "max-age=31536000",
    "crl": {
      "url": "http://c.pki.goog/we2/xuzt3PU9F_w.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 302
  },
  "elapsed_s": 6.2,
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
