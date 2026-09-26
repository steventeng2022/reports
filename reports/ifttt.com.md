# Security Audit Report — ifttt.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ifttt.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ifttt.com |
| Test date | 2026-09-26 18:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 0, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 8 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 9 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 7. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 8. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 9. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: hubspot-developer-verification=ODA3YjI3MGQtOTk1Ni00YzgxLWE2NjAtNzkyYjljZDU4MzVj; google-site-verification=sdwLeEbGkwDQnNef_ZybsYYO1nz4RksHjJlL4BFy97c; have-i-been-pwned-verification=1931e44ce46fd205b3806eff20a8b416
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of ifttt.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but ifttt.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 14 disallow path(s), e.g. /search/query/, /unsubscribe-from-applet/, /unsubscribe, /missing_link, /create/api/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://ifttt.com/ carries Cache-Control: max-age=0, public, s-maxage=42405 (plus ETag/Last-Modified freshness fields); shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.169.121.27 carries PTR server-3-169-121-27.tpe53.r.cloudfront.net. for ifttt.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "ifttt.com",
  "dns": {
    "a": [
      "3.169.121.27",
      "3.169.121.41",
      "3.169.121.2",
      "3.169.121.105"
    ],
    "aaaa": [
      "2600:9000:284c:8a00:1:b1c6:9e40:93a1",
      "2600:9000:284c:6000:1:b1c6:9e40:93a1",
      "2600:9000:284c:2800:1:b1c6:9e40:93a1",
      "2600:9000:284c:b400:1:b1c6:9e40:93a1",
      "2600:9000:284c:5200:1:b1c6:9e40:93a1",
      "2600:9000:284c:2c00:1:b1c6:9e40:93a1",
      "2600:9000:284c:fa00:1:b1c6:9e40:93a1",
      "2600:9000:284c:ca00:1:b1c6:9e40:93a1"
    ],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "aspmx3.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-1614.awsdns-09.co.uk.",
      "ns-425.awsdns-53.com.",
      "ns-1400.awsdns-47.org.",
      "ns-676.awsdns-20.net."
    ],
    "spf": [
      "hubspot-developer-verification=ODA3YjI3MGQtOTk1Ni00YzgxLWE2NjAtNzkyYjljZDU4MzVj",
      "v=MCPv1; k=ed25519; p=shhg+Sx/4D+wFvY1jwECmtgaGtpfAC5UDl0mb+mhdNg=",
      "MS=ms71593285",
      "edca106a3d3b474e87b5e47c25f607ec",
      "v=spf1 include:sendgrid.net include:_spf.google.com include:customeriomail.com include:mail.zendesk.com include:stspg-customer.com -all",
      "google-site-verification=sdwLeEbGkwDQnNef_ZybsYYO1nz4RksHjJlL4BFy97c",
      "have-i-been-pwned-verification=1931e44ce46fd205b3806eff20a8b416",
      "qrql38igvi0ce4abfi3on0vvke",
      "facebook-domain-verification=2gbh6mjor9buxlzajjq1hjbnksveuo",
      "_globalsign-domain-verification=rRjaOlcgFhBuUq2_dp1lnClpS6rvXrnUtycKh8GTEH",
      "google-site-verification=LaHtMW5vokuLBZBVhajjw-NS3aQbRMOOz92B-RM_4hQ",
      "status-page-domain-verification=btfx82x3lwwg",
      "a774vnn3gtgp35cvtd31idrcug",
      "google-site-verification=VdD3iT9gG8si3Zu4-crc2cMxN3b3oiRHtFcEAiDwTLc",
      "pinterest-site-verification=8e6e3928621ee8deeaa774c7569bb607",
      "globalsign-domain-verification=2D384BE73AFA22F600E2F2FD71973C63",
      "stripe-verification=d9aecd16a51b8f74a32c270d11a6bce84470c737c9d1e1de696edbce60ea7b47",
      "openai-domain-verification=dv-owUo2sHFljJJv2dyVfHqW3bb"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:arqctnow@ag.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=ifttt.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Oct 30 00:00:00 2025 GMT",
    "notAfter": "Nov 27 23:59:59 2026 GMT",
    "san": [
      "ifttt.com",
      "*.ifttt.com"
    ],
    "days_left": 62,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.121.27",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Automate. Save time. Get more done. - IFTTT"
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [
    {
      "domain": "ifttt.com",
      "samesite": "lax"
    },
    {
      "domain": "ifttt.com",
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.ifttt.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ifttt.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 302,
    "/.htaccess": 404,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "hubspot-developer-verification=ODA3YjI3MGQtOTk1Ni00YzgxLWE2NjAtNzkyYjljZDU4MzVj",
    "google-site-verification=sdwLeEbGkwDQnNef_ZybsYYO1nz4RksHjJlL4BFy97c",
    "have-i-been-pwned-verification=1931e44ce46fd205b3806eff20a8b416",
    "facebook-domain-verification=2gbh6mjor9buxlzajjq1hjbnksveuo",
    "_globalsign-domain-verification=rRjaOlcgFhBuUq2_dp1lnClpS6rvXrnUtycKh8GTEH"
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
      "not_before": "20251030000000",
      "not_after": "20261127235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/search/query/",
      "/unsubscribe-from-applet/",
      "/unsubscribe",
      "/missing_link",
      "/create/api/",
      "/dri/",
      "/search/query/",
      "/unsubscribe-from-applet/",
      "/unsubscribe",
      "/missing_link",
      "/create/api/",
      "/dri/",
      "/join",
      "/login"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-3-169-121-27.tpe53.r.cloudfront.net."
    ]
  },
  "elapsed_s": 7.3,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
