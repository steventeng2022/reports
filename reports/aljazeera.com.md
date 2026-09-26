# Security Audit Report — aljazeera.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://aljazeera.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | aljazeera.com |
| Test date | 2026-09-26 21:57 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

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
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 17 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 18 | info | CT1 | 7 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 19 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
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
- **Detail:** Header reveals: awselb/2.0
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=M3ur7621hvOQpenlhs-_qF01ecDrayRa1L5fBmtt4gM; google-site-verification=GYHvTiSZMugLVHza8hKcU73ZXvRA9EzfmCFhq3do7Gs; dtm-domain-verification=wI5BYcsOMyOViN0wvRdEzNPVL4nDlV9eVqDitvCHtOQ
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 16.192.191.107 carries PTR ec2-16-192-191-107.eu-north-1.compute.amazonaws.com. for aljazeera.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for aljazeera.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 17. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The aljazeera.com certificate lists an AIA OCSP responder (http://ocsp.sectigo.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 18. [INFO] 7 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: assets.america.aljazeera.com, staging.aljazeera.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 19. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: assets.america.aljazeera.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "aljazeera.com",
  "dns": {
    "a": [
      "16.192.191.107",
      "13.62.62.242",
      "16.16.240.252"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mailb.aljazeera.net (pref 1)",
      "maila.aljazeera.net (pref 1)"
    ],
    "ns": [
      "ns-744.awsdns-29.net.",
      "ns-1814.awsdns-34.co.uk.",
      "ns-321.awsdns-40.com.",
      "ns-1302.awsdns-34.org."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=M3ur7621hvOQpenlhs-_qF01ecDrayRa1L5fBmtt4gM",
      "google-site-verification=GYHvTiSZMugLVHza8hKcU73ZXvRA9EzfmCFhq3do7Gs",
      "dtm-domain-verification=wI5BYcsOMyOViN0wvRdEzNPVL4nDlV9eVqDitvCHtOQ",
      "google-site-verification=mBiRHB-ePRYuu3CKKTEG2bjDucKyvRY2GfDhV4n0wj4",
      "v=spf1 mx ptr mx:maila.aljazeera.net mx:mailb.aljazeera.net ip4:213.130.112.86/28 ip4:194.6.255.56/28 ip4:217.26.199.86 ip4:66.155.119.46 ip4:216.25.13.62 ip4:216.25.13.63 ip4:216.25.13.40/29 ip4:217.13.48.9/29 ip4:86.62.248.64/26 ip4:78.100.62.121 -all",
      "brevo-code:706289be26adb46268fc5315988644e6",
      "sendinblue-site-verification=4125135",
      "_qhc5ckndj0v0cuu4zloc8vg4nwd0fd0",
      "_g5iaej9do6s237elk6kpzb8u2xnkkq5"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc-mailauth@aljazeera.net; ruf=mailto:dmarc-mailfor@aljazeera.net; fo=s;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "countryName=QA, stateOrProvinceName=Ad Dawḩah, organizationName=Al Jazeera Media Network, commonName=*.aljazeera.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA OV R36",
    "notBefore": "Oct  9 00:00:00 2025 GMT",
    "notAfter": "Nov  3 23:59:59 2026 GMT",
    "san": [
      "*.aljazeera.com",
      "aljazeera.com"
    ],
    "days_left": 38,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "16.192.191.107",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.aljazeera.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.aljazeera.com:443/"
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
    "count": 7,
    "notable": [
      "assets.america.aljazeera.com",
      "staging.aljazeera.com"
    ],
    "sample": [
      "aljazeera.com",
      "assets.america.aljazeera.com",
      "staging.aljazeera.com",
      "surveys.aljazeera.com",
      "wordpress.aljazeera.com",
      "worldcup.aljazeera.com",
      "www.aljazeera.com"
    ],
    "dangling": [
      "assets.america.aljazeera.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=M3ur7621hvOQpenlhs-_qF01ecDrayRa1L5fBmtt4gM",
    "google-site-verification=GYHvTiSZMugLVHza8hKcU73ZXvRA9EzfmCFhq3do7Gs",
    "dtm-domain-verification=wI5BYcsOMyOViN0wvRdEzNPVL4nDlV9eVqDitvCHtOQ",
    "google-site-verification=mBiRHB-ePRYuu3CKKTEG2bjDucKyvRY2GfDhV4n0wj4",
    "sendinblue-site-verification=4125135"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": "http://ocsp.sectigo.com",
      "not_before": "20251009000000",
      "not_after": "20261103235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-16-192-191-107.eu-north-1.compute.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.aljazeera.com:443/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 38.6,
  "rechecked": "2026-09-26 21:56 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- Findings are reported against the public program scope; submission through the program tracker is pending.
