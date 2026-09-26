# Security Audit Report — adage.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://adage.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | adage.com |
| Test date | 2026-09-26 17:38 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 4, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

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
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): usb. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=uWzYibDTuhjliXGRiMnMEthKIS6O5mnJViVhGIOvK28; anthropic-domain-verification-pg50pw=UwO6bTKI23RICT2yieNZizAJB; lucidlink-verification=J1CHE4K03BM1Q64NFPMW63KC24
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of adage.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "adage.com",
  "dns": {
    "a": [
      "184.26.127.138",
      "184.26.127.144"
    ],
    "aaaa": [
      "2001:b034:1c:200::d247:e348",
      "2001:b034:1c:200::d247:e338"
    ],
    "cname": null,
    "mx": [
      "usb-smtp-inbound-1.mimecast.com (pref 10)",
      "usb-smtp-inbound-2.mimecast.com (pref 60)"
    ],
    "ns": [
      "connie.ns.cloudflare.com.",
      "kurt.ns.cloudflare.com."
    ],
    "spf": [
      "v=spf1 include:spf.crain.com include:_spf.clickshare.com include:aspmx.pardot.com include:usb._netblocks.mimecast.com ~all",
      "MS=ms52345011",
      "bw=A0toi1iKzrmRS2jxukTxOo6KI3d7V7eoIzDw5G7ubw5s",
      "google-site-verification=uWzYibDTuhjliXGRiMnMEthKIS6O5mnJViVhGIOvK28",
      "anthropic-domain-verification-pg50pw=UwO6bTKI23RICT2yieNZizAJB",
      "lucidlink-verification=J1CHE4K03BM1Q64NFPMW63KC24",
      "google-site-verification=69bymnCN1yRQSpHf-DQz5sLMlqQ0GuCspakaXRLBVZg"
    ],
    "dmarc": [
      "v=DMARC1; p=none;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=crain.web.arc-cdn.net",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR2",
    "notBefore": "Aug 21 13:48:19 2026 GMT",
    "notAfter": "Nov 19 13:48:18 2026 GMT",
    "san": [
      "adage.com",
      "arcxp-dev.adage.com",
      "arcxp-dev.automobilwoche.de",
      "arcxp-dev.autonews.com",
      "arcxp-dev.chicagobusiness.com",
      "arcxp-dev.craincurrency.com",
      "arcxp-dev.crainscleveland.com",
      "arcxp-dev.crainsdetroit.com",
      "arcxp-dev.crainsgrandrapids.com",
      "arcxp-dev.crainsnewyork.com",
      "arcxp-dev.genomeweb.com",
      "arcxp-dev.hartenergy.com",
      "arcxp-dev.modernhealthcare.com",
      "arcxp-dev.pionline.com",
      "arcxp-dev.plasticsnews.com",
      "arcxp-dev.rubbernews.com",
      "arcxp-dev.tirebusiness.com",
      "arcxp-dev.utech-polyurethane.com",
      "arcxp-prod.automobilwoche.de",
      "arcxp-prod.craincurrency.com",
      "arcxp-prod.crainsgrandrapids.com",
      "arcxp-prod.genomeweb.com",
      "arcxp-prod.hartenergy.com",
      "arcxp-prod.modernhealthcare.com",
      "arcxp-prod.pionline.com",
      "arcxp-sandbox.adage.com",
      "arcxp-sandbox.automobilwoche.de",
      "arcxp-sandbox.autonews.com",
      "arcxp-sandbox.chicagobusiness.com",
      "arcxp-sandbox.craincurrency.com",
      "arcxp-sandbox.crainscleveland.com",
      "arcxp-sandbox.crainsdetroit.com",
      "arcxp-sandbox.crainsgrandrapids.com",
      "arcxp-sandbox.crainsnewyork.com",
      "arcxp-sandbox.genomeweb.com",
      "arcxp-sandbox.hartenergy.com",
      "arcxp-sandbox.modernhealthcare.com",
      "arcxp-sandbox.pionline.com",
      "arcxp-sandbox.plasticsnews.com",
      "arcxp-sandbox.rubbernews.com",
      "arcxp-sandbox.tirebusiness.com",
      "arcxp-sandbox.utech-polyurethane.com",
      "arcxp-stage.adage.com",
      "arcxp-stage.automobilwoche.de",
      "arcxp-stage.autonews.com",
      "arcxp-stage.chicagobusiness.com",
      "arcxp-stage.craincurrency.com",
      "arcxp-stage.crainscleveland.com",
      "arcxp-stage.crainsdetroit.com",
      "arcxp-stage.crainsgrandrapids.com",
      "arcxp-stage.crainsnewyork.com",
      "arcxp-stage.genomeweb.com",
      "arcxp-stage.hartenergy.com",
      "arcxp-stage.modernhealthcare.com",
      "arcxp-stage.pionline.com",
      "arcxp-stage.plasticsnews.com",
      "arcxp-stage.rubbernews.com",
      "arcxp-stage.tirebusiness.com",
      "arcxp-stage.utech-polyurethane.com",
      "crain-adage-dev.web.arc-cdn.net",
      "crain-adage-prod.web.arc-cdn.net",
      "crain-adage-sandbox.web.arc-cdn.net",
      "crain-adage-staging.web.arc-cdn.net",
      "crain-automobilwoche-sandbox.web.arc-cdn.net",
      "crain-automobilwoche-staging.web.arc-cdn.net",
      "crain-automotivenews-dev.web.arc-cdn.net",
      "crain-automotivenews-prod.web.arc-cdn.net",
      "crain-automotivenews-sandbox.web.arc-cdn.net",
      "crain-automotivenews-staging.web.arc-cdn.net",
      "crain-crain-dev.web.arc-cdn.net",
      "crain-crain-prod.web.arc-cdn.net",
      "crain-crain-sandbox.web.arc-cdn.net",
      "crain-crain-staging.web.arc-cdn.net",
      "crain.web.arc-cdn.net",
      "www.adage.com",
      "www.automobilwoche.de",
      "www.autonews.com",
      "www.chicagobusiness.com",
      "www.craincurrency.com",
      "www.crainscleveland.com",
      "www.crainsdetroit.com",
      "www.crainsgrandrapids.com",
      "www.crainsnewyork.com",
      "www.genomeweb.com",
      "www.hartenergy.com",
      "www.modernhealthcare.com",
      "www.pionline.com",
      "www.plasticsnews.com",
      "www.rubbernews.com",
      "www.sustainableplastics.com",
      "www.tirebusiness.com",
      "www.utech-polyurethane.com"
    ],
    "days_left": 53,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "184.26.127.138",
    "open": []
  },
  "https": {
    "status": 403,
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
      "origin": "https://sub.adage.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 403
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 403,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 403,
    "/security.txt": 403,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=uWzYibDTuhjliXGRiMnMEthKIS6O5mnJViVhGIOvK28",
    "anthropic-domain-verification-pg50pw=UwO6bTKI23RICT2yieNZizAJB",
    "lucidlink-verification=J1CHE4K03BM1Q64NFPMW63KC24",
    "google-site-verification=69bymnCN1yRQSpHf-DQz5sLMlqQ0GuCspakaXRLBVZg"
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
      "aia_ocsp": null
    }
  },
  "elapsed_s": 5.0,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
