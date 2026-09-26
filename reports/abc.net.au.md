# Security Audit Report — abc.net.au

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://abc.net.au/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | abc.net.au |
| Test date | 2026-09-26 18:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

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
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | CT1 | 338 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 17 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
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
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

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
- **Detail:** Apex TXT records with verification/token content: openai-domain-verification=dv-A6eDZvBKglVN8S81SVfxEWjh; logmein-verification-code=2aafe7d0-e0e8-474e-b565-25f09e4b52ef; adobe-idp-site-verification=7c3065b8-a1ac-4df8-8440-8ae4a2b371e1
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of abc.net.au has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.209.216.141 carries PTR a23-209-216-141.deploy.static.akamaitechnologies.com. for abc.net.au.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] 338 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.abc.net.au, api.iview.abc.net.au, api.rex.abc.net.au, api.seesaw.abc.net.au, app.abc.net.au, apps.abc.net.au, auth.confluence.c2.abc.net.au, beta.abc.net.au, careers.abc.net.au, cdn.audience-mms-processor-nonp.c0.abc.net.au
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 17. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: app.abc.net.au; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "abc.net.au",
  "dns": {
    "a": [
      "23.209.216.141"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-0036d701.gslb.pphosted.com (pref 10)",
      "mxb-0036d701.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "eur2.akam.net.",
      "asia1.akam.net.",
      "ns1-31.akam.net.",
      "eur3.akam.net.",
      "ns1-129.akam.net.",
      "eur5.akam.net.",
      "usw1.akam.net.",
      "usw5.akam.net."
    ],
    "spf": [
      "_ypyfvza3k9d012wozvcpqr2rl5hgwax",
      "MS=ms97238178",
      "MS=F3CCB183E28279EA6BFB729BB36F156C93E1E6FC",
      "openai-domain-verification=dv-A6eDZvBKglVN8S81SVfxEWjh",
      "logmein-verification-code=2aafe7d0-e0e8-474e-b565-25f09e4b52ef",
      "_6zqpkv8jv9wixx2iahc3c9l73xzlcq3",
      "wmwgwl7t2p9c0pyqjtxg21zv07sjkw0z",
      "_mpsr69of9h3phkpg1oo4pkg7z9o13u8",
      "adobe-idp-site-verification=7c3065b8-a1ac-4df8-8440-8ae4a2b371e1",
      "security_contact=https://ab.co/security-contact",
      "facebook-domain-verification=wetfyk60byzwzxc6af5ct4iidciiz8",
      "hpe-greenlake-domain-verification=5a79544f6b576334325571625553586569355537544a69367939324271775968",
      "segment-site-verification=CPDEMeOkLajeqEcfuKs0TMeSQM8S4K9u",
      "Ki*!8fZN^6$3kPjwdj4lGl%d^AJtICghTa$@cDmHSrGPv%JiQfK#bUJ2464UFJEds*RdmDAi%7poA57UwIJH#BI82Tsg@M!KE4I",
      "security_policy=https://ab.co/security-guidelines",
      "successfactors-site-verification=ZWY4YWNhODM1YTI2Y2FlNzAyMmIzYTRjODcyMWY0MGJjM2ViMzU5OTA0NTdhZGY3MTRjMWM1MWQzMGU5ZmVjOA==",
      "jamf-site-verification=uatZyaF6YBPkZV-hoGjIDg",
      "DS_GUID=1f556b4d-4242-48a2-98ec-8b5389b9768a",
      "docker-verification=2c63eedd-5a73-4165-b8a3-1581ddf10029",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
      "openai-domain-verification=dv-3cs5FvAqthq1oIovgoLAvJpO",
      "anthropic-domain-verification-j2g448=j6ujaV7B2ctVhXdNRWCAbgWQB",
      "atlassian-domain-verification=VqcGTxT7+T2pb61t6YK69euiLYhHFIeqmEZhmZ1kn+Nw9MDeCxVvnthHJaOyuh53",
      "hcte5z9aRQBXzsiYoLbb2H6OXB/39P1lZ9FAUWYSjzh/XVWNMZgKjjMw0Qo9CBFGWalVAFV/pTFQRwZXJQmlTw==",
      "meltwater_sso_20220706_TRITON-9530",
      "google-site-verification=7054D-8q7ysCi8XYhwx8gZOjJJoYZpbcN5mSRYsKznA",
      "google-site-verification=Fe7MviHWN97I2rkSkD-uHqnXoRle0l60KrKG_qiu4EQ",
      "google-site-verification=YODbrd1vAD6Bvvh0nVqJ90UhzAmn9PY1JbZiEFCNnFg",
      "docusign=5193e34f-7907-4a09-8a2c-8e6059238790",
      "google-site-verification=hE1kILZtpqkyPs5Szz0KpVbNaTiprJyPVeCfNB1D5-g"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=AU, stateOrProvinceName=New South Wales, localityName=Ultimo, organizationName=Australian Broadcasting Corporation, commonName=abc.net.au",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "May  7 00:00:00 2026 GMT",
    "notAfter": "Nov 21 23:59:59 2026 GMT",
    "san": [
      "abc.net.au",
      "*.abc-cdn.net.au",
      "*.abc-host.net.au",
      "*.abc-prod.net.au",
      "*.abc-stage.net.au",
      "*.abc-test.net.au",
      "*.abc-uat.net.au",
      "*.abc.net.au",
      "*.abcradio.net.au",
      "*.c0.abc.net.au",
      "*.c1.abc.net.au",
      "*.c2.abc.net.au",
      "*.iview.abc-prod.net.au",
      "*.iview.abc-stage.net.au",
      "*.iview.abc-test.net.au",
      "*.iview.abc-uat.net.au",
      "*.iview.abc.net.au",
      "*.test.abc.net.au",
      "*.wcms-np.abc-cdn.net.au",
      "*.wcms.abc-cdn.net.au",
      "abc.au",
      "abc.gov.au",
      "abcaustralia.net.au",
      "api.rex.abc-test.net.au",
      "api.rex.abc.net.au",
      "api.seesaw.abc.net.au",
      "bamboo.ss.c0.abc.net.au",
      "bitbucket.ss.c0.abc.net.au",
      "click.mail-list.abc.net.au",
      "clicks.e.email.abc.net.au",
      "control-panel.rex.abc-test.net.au",
      "control-panel.rex.abc.net.au",
      "developers.digital.abc.net.au",
      "ios.tviview.abc.net.au",
      "ios.tviview.iview.abc-prod.net.au",
      "ios.tviview.iview.abc-stage.net.au",
      "ios.tviview.iview.abc-test.net.au",
      "livemusic.triplej.abc-prod.net.au",
      "livemusic.triplej.abc-test.net.au",
      "livemusicclearance.triplej.abc-prod.net.au",
      "livemusicclearance.triplej.abc-test.net.au",
      "pub.mail-list.abc.net.au",
      "streaming.c3.abc.net.au",
      "test.abcaustralia.net.au",
      "triplejunearthed.com",
      "www.abcaustralia.net.au",
      "www.abccommercial.com",
      "www.cdn.abc.net.au",
      "www.iviewsupport.abc.net.au",
      "www.triplejunearthed.com"
    ],
    "days_left": 56,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.209.216.141",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.abc.net.au",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.abc.net.au/"
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
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 338,
    "notable": [
      "api.abc.net.au",
      "api.iview.abc.net.au",
      "api.rex.abc.net.au",
      "api.seesaw.abc.net.au",
      "app.abc.net.au",
      "apps.abc.net.au",
      "auth.confluence.c2.abc.net.au",
      "beta.abc.net.au",
      "careers.abc.net.au",
      "cdn.audience-mms-processor-nonp.c0.abc.net.au",
      "cdn.audience-mms-processor-prod.c0.abc.net.au",
      "cdn.iview.abc.net.au",
      "centres.shop.abc.net.au",
      "help.abc.net.au",
      "imanage.apps.abc.net.au"
    ],
    "sample": [
      "abc.net.au",
      "abc908.aus.aunty.abc.net.au",
      "abcsccmcmg.abc.net.au",
      "abcvpn.abc.net.au",
      "about.abc.net.au",
      "access.abc.net.au",
      "accounts-api.abc.net.au",
      "airflow-nonp.ad-np.c0.abc.net.au",
      "airflow-prod.ad.c0.abc.net.au",
      "airflow-v2-nonp.ad-np.c0.abc.net.au",
      "airflow-v2-prod.ad.c0.abc.net.au",
      "aisawards.abc.net.au",
      "amp.abc.net.au",
      "api-archives-stills.content-np.c0.abc.net.au",
      "api-archives.content-np.c0.abc.net.au",
      "api-archives.content-st.c0.abc.net.au",
      "api-archives.content.c0.abc.net.au",
      "api-coda.photos-np.c0.abc.net.au",
      "api-coda.photos-st.c0.abc.net.au",
      "api-coda.photos.c0.abc.net.au"
    ],
    "dangling": [
      "app.abc.net.au"
    ]
  },
  "apex_txt": [
    "openai-domain-verification=dv-A6eDZvBKglVN8S81SVfxEWjh",
    "logmein-verification-code=2aafe7d0-e0e8-474e-b565-25f09e4b52ef",
    "adobe-idp-site-verification=7c3065b8-a1ac-4df8-8440-8ae4a2b371e1",
    "facebook-domain-verification=wetfyk60byzwzxc6af5ct4iidciiz8",
    "hpe-greenlake-domain-verification=5a79544f6b576334325571625553586569355537544a69"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260507000000",
      "not_after": "20261121235959"
    }
  },
  "x12": {
    "status": 403,
    "ptr": [
      "a23-209-216-141.deploy.static.akamaitechnologies.com."
    ]
  },
  "elapsed_s": 6.5,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
