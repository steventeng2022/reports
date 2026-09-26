# Security Audit Report — amazon.co.jp

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://amazon.co.jp/ |
| Bug bounty program | Amazon |
| Listed scope domain | amazon.co.jp |
| Test date | 2026-09-26 18:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 5, Info: 14)

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
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | CT1 | 125 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 19 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Server
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
- **Detail:** Header reveals: Server
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=dYnsx1NbvPPP-pOh2ahq-5Mke8grHPEQg7MtBcugwWQ; google-gws-recovery-domain-verification=70440261; cisco-ci-domain-verification=685cb2edc64df221f293cac7a545b2af41f5a0323021c164409
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of amazon.co.jp has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 274 disallow path(s), e.g. /dp/product-availability/, /dp/rate-this-item/, /exec/obidos/account-access-login, /exec/obidos/change-style, /exec/obidos/di
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 18.246.99.104 carries PTR ec2-18-246-99-104.us-west-2.compute.amazonaws.com. for amazon.co.jp.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] 125 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.sandbox.amazon.co.jp, files.amazon.co.jp, help.amazon.co.jp, pay.amazon.co.jp, support.amazon.co.jp
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 19. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: files.amazon.co.jp; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "amazon.co.jp",
  "dns": {
    "a": [
      "18.246.99.104",
      "18.246.98.187",
      "18.246.95.183"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "amazon-smtp.amazon.com (pref 10)"
    ],
    "ns": [
      "ns-1527.awsdns-62.org.",
      "ns-587.awsdns-09.net.",
      "ns-177.awsdns-22.com.",
      "ns-1736.awsdns-25.co.uk."
    ],
    "spf": [
      "google-site-verification=dYnsx1NbvPPP-pOh2ahq-5Mke8grHPEQg7MtBcugwWQ",
      "google-gws-recovery-domain-verification=70440261",
      "ZOOM_verify_lnnruOzf0XRC57uVT7umvK",
      "cisco-ci-domain-verification=685cb2edc64df221f293cac7a545b2af41f5a0323021c164409272a0a1e544b6",
      "sending_domain229492=e7b03d2b7d1dcf19baad718bb0df19efe8dee7f648c953a5185f25f39d5f0a8f",
      "MS=ms91867689",
      "google-site-verification=6COB0DTBjZ-FYdl2H-ypIXMjf5631sEYVeEhTUkb4cU",
      "v=spf1 include:amazon.com include:spf-bma.mpme.jp -all",
      "box-domain-verification=ffea95cd0e0d61c302198367155b07e74fd534fa1d867662dc9bf9969b6f535d",
      "sending_domain229492=ab2381d1cadbdb0ca117c94ff7ef507185694417c3cc252cdcb3146840bd798f",
      "MS=ms86838901",
      "sending_domain1003771=974fbdaf1c222454080d32f138639599954ab43e3ad744f585238bf139c223d1",
      "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbDvoGpRaIwj/tgPH",
      "google-gws-recovery-domain-verification=69412678",
      "facebook-domain-verification=q0vtskklb65bdw766sy92dffo95y08",
      "docker-verification=06bc28d2-bb7d-46f8-8788-b0fe306af0e1",
      "sending_domain608861=911f4b33f6b6d011b0ceaaaf87cd07371cdc116d80d3a4f710f95bea9c19e084",
      "google-site-verification=4co3PF8vuUVE6aPUXlE8XDJgihi5vzb9SXFdnyGrGSI",
      "autodesk-domain-verification=nT3SNNqpmwBfAkjiIy0S",
      "sending_domain608861=c27592c67e261103651362999201d708cfcdf4705a1d80672d7b0d8324aed1aa",
      "bluebeam-verification=fs3mpshnh21px44nq53xj0z3tj6ly6",
      "adobe-idp-site-verification=b6bcd3e5aaffc63607c8bf75744d9a0d1febc50dd7f389428e2ae476c9ba8814",
      "google-gws-recovery-domain-verification=68063601",
      "sending_domain1003771=9260d9210bf7f24d01e19fdd01c532869e915954bede5057cd3d7e1b46df352f",
      "cisco-ci-domain-verification=175519cd5d9f724ae360327570d03e520231c232f77bc6ef59aa1317a9ab27f5",
      "liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo",
      "spf2.0/pra include:amazon.com include:spf-bma.mpme.jp -all",
      "kahoot-domain-verification=05f08b60093b698395d238068d3bd84e7b0ae240df10947ddee72326c75856ed",
      "wrike-verification=MzI3NzM2ODo2NDk5MjE4NjQ2MWJmOTEwMGMxM2MzNzJmNWJlY2U5ZDU4MmVlNzQ2NWU4MTY5OWJjMjlmYjQ4Mjc5M2JiMzky",
      "canva-site-verification=46MrwqUDYU-KF1ZLxnrm5g"
    ],
    "dmarc": [
      "v=DMARC1;",
      "p=quarantine;",
      "pct=100;",
      "rua=mailto:report@dmarc.amazon.com;",
      "ruf=mailto:report@dmarc.amazon.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.peg.a2z.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=GeoTrust TLS RSA CA G1",
    "notBefore": "Sep 20 00:00:00 2026 GMT",
    "notAfter": "Apr  5 23:59:59 2027 GMT",
    "san": [
      "amazon.co.uk",
      "uedata.amazon.co.uk",
      "www.amazon.co.uk",
      "origin-www.amazon.co.uk",
      "*.peg.a2z.com",
      "amazon.com",
      "amzn.com",
      "uedata.amazon.com",
      "us.amazon.com",
      "www.amazon.com",
      "www.amzn.com",
      "corporate.amazon.com",
      "buybox.amazon.com",
      "iphone.amazon.com",
      "yp.amazon.com",
      "home.amazon.com",
      "origin-www.amazon.com",
      "origin2-www.amazon.com",
      "buckeye-retail-website.amazon.com",
      "huddles.amazon.com",
      "amazon.de",
      "www.amazon.de",
      "origin-www.amazon.de",
      "amazon.co.jp",
      "amazon.jp",
      "www.amazon.jp",
      "www.amazon.co.jp",
      "origin-www.amazon.co.jp",
      "*.aa.peg.a2z.com",
      "*.ab.peg.a2z.com",
      "*.ac.peg.a2z.com",
      "origin-www.amazon.com.au",
      "www.amazon.com.au",
      "*.bz.peg.a2z.com",
      "amazon.com.au",
      "origin2-www.amazon.co.jp",
      "edgeflow.aero.4d5ad1d2b-frontier.amazon.co.jp",
      "edgeflow.aero.04f01a85e-frontier.amazon.com.au",
      "edgeflow.aero.47cf2c8c9-frontier.amazon.com",
      "edgeflow.aero.abe2c2f23-frontier.amazon.de",
      "edgeflow.aero.bfbdc3ca1-frontier.amazon.co.uk",
      "edgeflow-dp.aero.4d5ad1d2b-frontier.amazon.co.jp",
      "edgeflow-dp.aero.04f01a85e-frontier.amazon.com.au",
      "edgeflow-dp.aero.47cf2c8c9-frontier.amazon.com",
      "edgeflow-dp.aero.bfbdc3ca1-frontier.amazon.co.uk",
      "edgeflow-dp.aero.abe2c2f23-frontier.amazon.de",
      "shop.business.amazon.com"
    ],
    "days_left": 191,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "18.246.99.104",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Server"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.amazon.co.jp",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://amazon.co.jp/"
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
    "count": 125,
    "notable": [
      "api.sandbox.amazon.co.jp",
      "files.amazon.co.jp",
      "help.amazon.co.jp",
      "pay.amazon.co.jp",
      "support.amazon.co.jp"
    ],
    "sample": [
      "a9g-api.amazon.co.jp",
      "aax-fe.amazon.co.jp",
      "ab-stage.amazon.co.jp",
      "account-status.amazon.co.jp",
      "account-vdp.amazon.co.jp",
      "account.kdp.amazon.co.jp",
      "account.kep.amazon.co.jp",
      "account.videocentral.amazon.co.jp",
      "account.videodirect.amazon.co.jp",
      "advantage.amazon.co.jp",
      "aeswidget.amazon.co.jp",
      "affiliate.amazon.co.jp",
      "alexa-skills-beta-eu.amazon.co.jp",
      "alexa-skills-na.amazon.co.jp",
      "amazon.co.jp",
      "amg.amazon.co.jp",
      "amh.amazon.co.jp",
      "api-amazondevices.amazon.co.jp",
      "api-key.amazon.co.jp",
      "api-sandbox.amazon.co.jp"
    ],
    "dangling": [
      "files.amazon.co.jp"
    ]
  },
  "apex_txt": [
    "google-site-verification=dYnsx1NbvPPP-pOh2ahq-5Mke8grHPEQg7MtBcugwWQ",
    "google-gws-recovery-domain-verification=70440261",
    "cisco-ci-domain-verification=685cb2edc64df221f293cac7a545b2af41f5a0323021c164409",
    "google-site-verification=6COB0DTBjZ-FYdl2H-ypIXMjf5631sEYVeEhTUkb4cU",
    "box-domain-verification=ffea95cd0e0d61c302198367155b07e74fd534fa1d867662dc9bf996"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20260920000000",
      "not_after": "20270405235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/dp/product-availability/",
      "/dp/rate-this-item/",
      "/exec/obidos/account-access-login",
      "/exec/obidos/change-style",
      "/exec/obidos/di",
      "/exec/obidos/dt",
      "/exec/obidos/dt/assoc/handle-buy-box",
      "/exec/obidos/flex-sign-in",
      "/exec/obidos/handle-buy-box",
      "/exec/obidos/refer-a-friend-login",
      "/exec/obidos/subst/associates/join",
      "/exec/obidos/subst/marketplace/sell-your-collection.html",
      "/exec/obidos/subst/marketplace/sell-your-stuff.html",
      "/exec/obidos/subst/partners/friends/access.html",
      "/exec/obidos/tg/cm/member/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-18-246-99-104.us-west-2.compute.amazonaws.com."
    ]
  },
  "elapsed_s": 19.8,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
