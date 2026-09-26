# Security Audit Report — lh3.googleusercontent.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://lh3.googleusercontent.com/ |
| Bug bounty program | Google |
| Listed scope domain | lh3.googleusercontent.com |
| Test date | 2026-09-26 18:54 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 12 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | CT1 | 1 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: fife
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

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Header reveals: fife
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 12. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.lh3.googleusercontent.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (j9o65tz8zzkz7p.lh3.googleusercontent.com and uaddhfcg4qlbnv.lh3.googleusercontent.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of lh3.googleusercontent.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 142.251.170.132 carries PTR tc-in-f132.1e100.net. for lh3.googleusercontent.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] 1 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "lh3.googleusercontent.com",
  "dns": {
    "a": [
      "142.251.170.132"
    ],
    "aaaa": [
      "2404:6800:4008:c19::84"
    ],
    "cname": "googlehosted.l.googleusercontent.com.",
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
    "subject": "commonName=*.googleusercontent.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE2",
    "notBefore": "Sep 10 19:23:26 2026 GMT",
    "notAfter": "Dec  3 19:23:25 2026 GMT",
    "san": [
      "*.googleusercontent.com",
      "commondatastorage.googleapis.com",
      "*.commondatastorage.googleapis.com",
      "storage.googleapis.com",
      "*.storage.googleapis.com",
      "storage-p2.googleapis.com",
      "*.storage-p2.googleapis.com",
      "storage.mtls.googleapis.com",
      "*.appspot.com.storage.googleapis.com",
      "*.content-storage.googleapis.com",
      "*.content-storage-p2.googleapis.com",
      "*.content-storage-upload.googleapis.com",
      "*.content-storage-download.googleapis.com",
      "*.storage-upload.googleapis.com",
      "*.storage-download.googleapis.com",
      "blogspot.com",
      "*.blogspot.com",
      "bp.blogspot.com",
      "*.bp.blogspot.com",
      "doubleclickusercontent.com",
      "*.doubleclickusercontent.com",
      "ggpht.com",
      "*.ggpht.com",
      "googledrive.com",
      "*.googledrive.com",
      "*.googlesyndication.com",
      "*.safeframe.googlesyndication.com",
      "googleusercontent.com",
      "*.byoid.googleusercontent.com",
      "usercontent.goog",
      "*.usercontent.goog",
      "*.ucp.usercontent.goog",
      "*.h5games.usercontent.goog",
      "*.playables.usercontent.goog",
      "*.allownetworkplayables.usercontent.goog",
      "*.safeframe.usercontent.goog",
      "*.sandbox.usercontent.goog",
      "*.scf.usercontent.goog",
      "*.isolated.usercontent.goog",
      "*.static.usercontent.goog",
      "*.ads-static.usercontent.goog",
      "*.executionbox.usercontent.goog",
      "*.aiplayables.usercontent.goog",
      "*.playground.usercontent.goog",
      "*.labs-studios.usercontent.goog",
      "rbm-smb-experience.business.usercontent.goog",
      "rbm-smb-experience-autopush.business.usercontent.goog",
      "manifest.c.mail.googleusercontent.com",
      "manifest.lh3-da.googleusercontent.com",
      "manifest.lh3-db.googleusercontent.com",
      "manifest.lh3-dc.googleusercontent.com",
      "manifest.lh3-dd.googleusercontent.com",
      "manifest.lh3-de.googleusercontent.com",
      "manifest.lh3-df.googleusercontent.com",
      "manifest.lh3-dg.googleusercontent.com",
      "manifest.lh3-dz.googleusercontent.com",
      "manifest.lh3.googleusercontent.com",
      "manifest.lh3.photos.google.com",
      "googleweblight.com",
      "*.googleweblight.com",
      "translate.goog",
      "*.translate.goog",
      "*.search.translate.goog",
      "*.dev.amp4mail.googleusercontent.com",
      "*.prod.amp4mail.googleusercontent.com",
      "*.playground.amp4mail.googleusercontent.com",
      "*.playground-internal.amp4mail.googleusercontent.com",
      "*.aiplatform-notebook.googleusercontent.com",
      "*.aiplatform-training.googleusercontent.com",
      "*.aiplatform-training.byoid.googleusercontent.com",
      "*.audiobook-additional-material-staging.googleusercontent.com",
      "*.audiobook-additional-material.googleusercontent.com",
      "*.apps.googleusercontent.com",
      "*.safenup.googleusercontent.com",
      "*.sandbox.googleusercontent.com",
      "*.backupdr.googleusercontent.com",
      "*.backupdr.byoid.googleusercontent.com",
      "*.backupdr-staging.googleusercontent.com",
      "*.backupdr-staging.byoid.googleusercontent.com",
      "*.backupdr-autopush.googleusercontent.com",
      "*.backupdr-autopush.byoid.googleusercontent.com",
      "*.backupdr-dev.googleusercontent.com",
      "*.backupdr-dev.byoid.googleusercontent.com",
      "*.backupdr-sandbox.googleusercontent.com",
      "*.backupdr-sandbox.byoid.googleusercontent.com",
      "*.composer.googleusercontent.com",
      "*.composer.byoid.googleusercontent.com",
      "*.composer-staging.googleusercontent.com",
      "*.composer-staging.byoid.googleusercontent.com",
      "*.composer-qa.googleusercontent.com",
      "*.composer-qa.byoid.googleusercontent.com",
      "*.composer-dev.googleusercontent.com",
      "*.composer-dev.byoid.googleusercontent.com",
      "*.dataplex.googleusercontent.com",
      "*.dataplex-staging.googleusercontent.com",
      "*.dataplex-dev.googleusercontent.com",
      "*.dataproc.googleusercontent.com",
      "*.dataproc.byoid.googleusercontent.com",
      "*.dataproc-image-staging.googleusercontent.com",
      "*.dataproc-image-staging.byoid.googleusercontent.com",
      "*.dataproc-staging.googleusercontent.com",
      "*.dataproc-staging.byoid.googleusercontent.com",
      "*.dataproc-test.googleusercontent.com",
      "*.dataproc-test.byoid.googleusercontent.com",
      "*.datafusion.googleusercontent.com",
      "*.datafusion.byoid.googleusercontent.com",
      "*.datafusion-staging.googleusercontent.com",
      "*.datafusion-staging.byoid.googleusercontent.com",
      "*.datafusion-dev.googleusercontent.com",
      "*.datafusion-dev.byoid.googleusercontent.com",
      "*.datafusion-api.googleusercontent.com",
      "*.datafusion-api.byoid.googleusercontent.com",
      "*.datafusion-api-staging.googleusercontent.com",
      "*.datafusion-api-staging.byoid.googleusercontent.com",
      "*.datafusion-api-dev.googleusercontent.com",
      "*.datafusion-api-dev.byoid.googleusercontent.com",
      "*.gsc.googleusercontent.com",
      "*.gcc.googleusercontent.com",
      "*.tuf.googleusercontent.com",
      "*.tuf-autopush.googleusercontent.com",
      "*.tuf-dev.googleusercontent.com",
      "*.tuf-staging.googleusercontent.com",
      "*.fuchsia-updates.googleusercontent.com",
      "*.fuchsia-updates-autopush.googleusercontent.com",
      "*.fuchsia-updates-autopush-qual.googleusercontent.com",
      "*.fuchsia-updates-dev.googleusercontent.com",
      "*.fuchsia-updates-staging.googleusercontent.com",
      "*.machinelearningtools.googleusercontent.com",
      "*.machinelearningtools-staging.googleusercontent.com",
      "*.machinelearningtools-autopush.googleusercontent.com",
      "*.machinelearningtools-dev.googleusercontent.com",
      "*.mos-updates.googleusercontent.com",
      "*.mos-updates-autopush.googleusercontent.com",
      "*.mos-updates-autopush-qual.googleusercontent.com",
      "*.mos-updates-dev.googleusercontent.com",
      "*.mos-updates-staging.googleusercontent.com",
      "*.notebooks.googleusercontent.com",
      "*.notebooks.byoid.googleusercontent.com",
      "*.pipelines.googleusercontent.com",
      "*.tensorboard.googleusercontent.com",
      "*.tensorboard-autopush.googleusercontent.com",
      "*.tensorboard-dev.googleusercontent.com",
      "*.tensorboard-staging.googleusercontent.com",
      "*.tensorboard-test.googleusercontent.com",
      "*.kernels.googleusercontent.com",
      "*.kernels-staging.googleusercontent.com",
      "*.kernels-test.googleusercontent.com",
      "*.cloudshell.googleusercontent.com",
      "*.cloudworkstations.googleusercontent.com",
      "*.vast.googleusercontent.com",
      "*.vast-staging.googleusercontent.com",
      "*.vast-autopush.googleusercontent.com",
      "*.vast-sandbox.googleusercontent.com"
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
    "ip": "142.251.170.132",
    "open": []
  },
  "https": {
    "status": 400,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: fife"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.lh3.googleusercontent.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 400
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 400",
    "/redirect?next=https://evil-auditor.example/x -> 400",
    "/go?url=https://evil-auditor.example/x -> 400",
    "/url?url=https://evil-auditor.example/x -> 400"
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
    "/server-status": 400,
    "/api/": 400
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 1,
    "notable": [],
    "sample": [
      "manifest.lh3.googleusercontent.com"
    ]
  },
  "wildcard_dns": true,
  "cname_chain": [
    "googlehosted.l.googleusercontent.com"
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
      "aia_ocsp": null,
      "not_before": "20260910192326",
      "not_after": "20261203192325"
    }
  },
  "x12": {
    "status": 400,
    "ptr": [
      "tc-in-f132.1e100.net."
    ]
  },
  "elapsed_s": 3.4,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
