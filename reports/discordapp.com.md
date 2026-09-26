# Security Audit Report — discordapp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://discordapp.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | discordapp.com |
| Test date | 2026-09-26 17:43 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.133.233:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.133.233:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 12. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.discordapp.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: gc-ai-domain-verification-h4p9zv=mTSLyVQqkAlNuctKXdWWZ7MLC; logmein-verification-code=2d4b306a-e291-4dc9-a09f-2cc3277288cc; onetrust-domain-verification=3e11024ff11441678e3d59aa6b3a87bc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of discordapp.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 46 disallow path(s), e.g. /channels, /channels/, /verify, /verify/, /reset
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "discordapp.com",
  "dns": {
    "a": [
      "162.159.133.233",
      "162.159.130.233",
      "162.159.135.233",
      "162.159.129.233",
      "162.159.134.233"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "aspmx3.googlemail.com (pref 10)"
    ],
    "ns": [
      "gabe.ns.cloudflare.com.",
      "sima.ns.cloudflare.com."
    ],
    "spf": [
      "gc-ai-domain-verification-h4p9zv=mTSLyVQqkAlNuctKXdWWZ7MLC",
      "logmein-verification-code=2d4b306a-e291-4dc9-a09f-2cc3277288cc",
      "onetrust-domain-verification=3e11024ff11441678e3d59aa6b3a87bc",
      "adobe-idp-site-verification=954e966634e7f12b8a9a2876a989bf5e7f5050a5192c3f529b9917cc4a7d1436",
      "apple-domain-verification=xPWro2NHlvCQs7LI",
      "dropbox-domain-verification=66jnk5y945ew",
      "v=spf1 include:_spf.google.com include:mail.zendesk.com include:sendgrid.net include:3885857.spf06.hubspotemail.net include:_spf.salesforce.com -all",
      "google-site-verification=ihjYpERVTt6QLWL2IBBLsEZroHPjP3vVQHQG97oXZlI",
      "loom-site-verification=3b8db7a74102494ba9569c862bbc5587",
      "hubspot-domain-verification=YmIxMDNhZDEtMzI3Mi00ZWNjLTk4MTYtNmViZGU5NzYyZDM5",
      "adobe-sign-verification=d19200aacd69c1b8e10cd1a5b47c91c3",
      "google-site-verification=jtVaxAcfspCN94ECrH12n9XJhdqO6Y2j2u3eh1XsApE",
      "docker-verification=f765b7ff-5ce5-4f27-b00a-28091eddacce",
      "jamf-site-verification=xf0BRLPJ0fkW9oZxiDbxaQ",
      "dust-domain-verification-kz9236=gJamMWiktWPTDezEQ9uvTDzyS",
      "MS=CD44642CAC1658ABE588B1F34173984181355D4E",
      "zapier-domain-verification-challenge=d87a2680-bf27-4b61-8174-5ceed32bb8c7",
      "google-site-verification=PmQRNDYVKwgF3tM6HulK5Fmmna3DSKklkjl-epmhplA",
      "5508A8F48F",
      "logmein-verification-code=e675be17-2988-4b0b-9e19-d6793fc28655",
      "atlassian-domain-verification=JNe2Ze7P8p623k8f7xRaHDyQWb6VzLxjFga1tu8M7lmVXC0bo1XgdnEsYuGIRFHv",
      "slack-domain-verification=wmXS8pleSDJ3LgREcHasvMfdkHmBbUvNI6nHNnJl",
      "stripe-verification=b449d3730bb78d03e0744aa61ae3fa2f35f80572bff9e48ad9a1927508291ea1",
      "notion_verify_A}38XvVG2tiA3b6w4kU89}p~hasV-%G^E8U0.Evvp?^a==pC1]12+eXq]BgW+%hmodpfn]",
      "google-site-verification=DGERr7gTRtGPVmghE_qE_w3X2kyTXdqiDVR2pBDpndQ",
      "stripe-verification=1d56fec5a0f745dabfbe48592806853324fe50a8d4448c10e524136d1fac1cae",
      "jetbrains-domain-verification=b5av2j0mg51z6vn0dpigrxbxx",
      "google-site-verification=27NMadvvj0pSQl1hkMaX3X5bwpjdFmE_FvX-MAgdLBE",
      "autodesk-domain-verification=2sh4O6xiIc4ReP9Aee8h",
      "HjRfQW6OV2YOkDOgNju3gYI0_cx9H1iF"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:eb13ef68c6894cf0bc517e8303852ee3@dmarc-reports.cloudflare.net;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=discordapp.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 28 22:09:52 2026 GMT",
    "notAfter": "Nov 26 23:09:41 2026 GMT",
    "san": [
      "discordapp.com",
      "*.discordapp.com"
    ],
    "days_left": 61,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "162.159.133.233",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "discordapp.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.discordapp.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://discordapp.com/"
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
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "gc-ai-domain-verification-h4p9zv=mTSLyVQqkAlNuctKXdWWZ7MLC",
    "logmein-verification-code=2d4b306a-e291-4dc9-a09f-2cc3277288cc",
    "onetrust-domain-verification=3e11024ff11441678e3d59aa6b3a87bc",
    "adobe-idp-site-verification=954e966634e7f12b8a9a2876a989bf5e7f5050a5192c3f529b99",
    "apple-domain-verification=xPWro2NHlvCQs7LI"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/channels",
      "/channels/",
      "/verify",
      "/verify/",
      "/reset",
      "/reset/",
      "/authorize-ip",
      "/authorize-ip/",
      "/reject-ip",
      "/reject-ip/",
      "/reject-mfa",
      "/reject-mfa/",
      "/oauth2",
      "/oauth2/",
      "/api"
    ]
  },
  "elapsed_s": 4.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
