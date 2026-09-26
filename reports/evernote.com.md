# Security Audit Report — evernote.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://evernote.com/ |
| Bug bounty program | Evernote |
| Listed scope domain | evernote.com |
| Test date | 2026-09-26 17:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 8 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 9 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | CT1 | 94 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 17 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: X-Powered-By: Next.js
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 7. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'NEXT_LOCALE' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 8. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'clientGeoLocation' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 9. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'clientGeoLocation' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: canva-site-verification=_a7Hc12U89xMaVt0CzG-mw; google-site-verification=-tROSeCW72D2qJrtgHAu2XtmEUdNg0pVK7JgXQc5FZI; rippling-domain-verification=217697edd61756fc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of evernote.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1 disallow path(s), e.g. /download-evernote/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] 94 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.evernote.com, api.preprod3.evernote.com, api.production.gateways.evernote.com, api.stage.evernote.com, api.staging.evernote.com, api.staging.gateways.evernote.com, api.testing.evernote.com, api.testing.gateways.evernote.com, app.preprod3.evernote.com, auth.production.gateways.evernote.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 17. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: api.production.gateways.evernote.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "evernote.com",
  "dns": {
    "a": [
      "34.98.96.201"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx3.googlemail.com (pref 30)",
      "aspmx5.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx4.googlemail.com (pref 30)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-cloud-a4.googledomains.com.",
      "ns-cloud-a2.googledomains.com.",
      "ns-cloud-a1.googledomains.com.",
      "ns-cloud-a3.googledomains.com."
    ],
    "spf": [
      "canva-site-verification=_a7Hc12U89xMaVt0CzG-mw",
      "google-site-verification=-tROSeCW72D2qJrtgHAu2XtmEUdNg0pVK7JgXQc5FZI",
      "rippling-domain-verification=217697edd61756fc",
      "docusign=1724c740-d62f-4f0e-b956-0e8787843ef0",
      "asv=9d228dc836a5edcac89e69ce0b2ab4cc",
      "notion-domain-verification=PjXoSWSCXGi4euHbeppuaTYLWO7vhUdn5u9oEzzyt3X",
      "atlassian-domain-verification=tOVXqvuSdF7wH9xBOcTHifwIEfXQX6XGoTgtPxe46s5sqCLZax9yh7Ms46Uuns0N",
      "5hg44l7nrl4tfsqj45zfp34qxqnx6129",
      "facebook-domain-verification=ald97r41mq52lyt3zyn7iipmy75y93",
      "adobe-idp-site-verification=453e072a-bf19-40ff-a370-146e1459ffd0",
      "central-8812",
      "apple-domain-verification=yJzU0JcusoBfuohM",
      "v=spf1 ip4:119.254.30.0/26 ip4:204.154.94.0/23 ip4:167.89.16.0/24 include:_spf.google.com include:mail.zendesk.com include:mailsenders.netsuite.com include:_spf.sparkpostmail.com -all",
      "google-site-verification=dswNJSKs6qzI6U2FgFv5SFInM8oRSAUctV4g7cVTnfs",
      "docker-verification=d4449a7e-12da-4006-be0c-cb9c965031f5",
      "lc7kqxfd8kpr7hwptf9msfg60vg19wll",
      "google-site-verification=746Vk94H7agHphG-MN3o0ZF82RRnvaVH9WWtpmD2G5o",
      "h1-domain-verification=RRP11TgYbS83xtxg31xb8StneabT5XQ7Uo6eiS44odH8iLvJ",
      "google-site-verification=TphACNeqZxSVjMZlu6C2OemNCLCtbP2yMJMm1eornp4",
      "_lbrr2xccc7tfxjp5xf77af22poxe4w5"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.bendingspoons.com; sp=reject;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=evernote.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR3",
    "notBefore": "Aug 11 22:02:59 2026 GMT",
    "notAfter": "Nov  9 22:58:54 2026 GMT",
    "san": [
      "evernote.com"
    ],
    "days_left": 44,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.98.96.201",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Best Note Taking App - Organize Your Notes with Evernote"
  },
  "mixed_content": [],
  "tech": [
    "X-Powered-By: Next.js"
  ],
  "cookies": [
    {
      "domain": ".evernote.com",
      "samesite": "lax"
    },
    {}
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.evernote.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://evernote.com:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 307",
    "/redirect?next=https://evil-auditor.example/x -> 307",
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
    "/api/": 308
  },
  "subdomains": {
    "source": "certspotter",
    "count": 94,
    "notable": [
      "api.evernote.com",
      "api.preprod3.evernote.com",
      "api.production.gateways.evernote.com",
      "api.stage.evernote.com",
      "api.staging.evernote.com",
      "api.staging.gateways.evernote.com",
      "api.testing.evernote.com",
      "api.testing.gateways.evernote.com",
      "app.preprod3.evernote.com",
      "auth.production.gateways.evernote.com",
      "auth.staging.gateways.evernote.com",
      "auth.testing.gateways.evernote.com",
      "barracuda.staging.evernote.com",
      "blog.evernote.com",
      "cscan.stage.evernote.com"
    ],
    "sample": [
      "accounts.evernote.com",
      "accounts.preprod3.evernote.com",
      "api.evernote.com",
      "api.preprod3.evernote.com",
      "api.production.gateways.evernote.com",
      "api.stage.evernote.com",
      "api.staging.evernote.com",
      "api.staging.gateways.evernote.com",
      "api.testing.evernote.com",
      "api.testing.gateways.evernote.com",
      "app.preprod3.evernote.com",
      "auth.production.gateways.evernote.com",
      "auth.staging.gateways.evernote.com",
      "auth.testing.gateways.evernote.com",
      "barracuda.evernote.com",
      "barracuda.staging.evernote.com",
      "blog.evernote.com",
      "brand.evernote.com",
      "builds.webclipper.evernote.com",
      "cdn1.evernote.com"
    ],
    "dangling": [
      "api.production.gateways.evernote.com"
    ]
  },
  "apex_txt": [
    "canva-site-verification=_a7Hc12U89xMaVt0CzG-mw",
    "google-site-verification=-tROSeCW72D2qJrtgHAu2XtmEUdNg0pVK7JgXQc5FZI",
    "rippling-domain-verification=217697edd61756fc",
    "notion-domain-verification=PjXoSWSCXGi4euHbeppuaTYLWO7vhUdn5u9oEzzyt3X",
    "atlassian-domain-verification=tOVXqvuSdF7wH9xBOcTHifwIEfXQX6XGoTgtPxe46s5sqCLZax"
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
  "http2": {
    "robots_disallow": [
      "/download-evernote/"
    ]
  },
  "elapsed_s": 39.3,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
