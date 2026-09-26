# Security Audit Report — amazon.ca

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://amazon.ca/ |
| Bug bounty program | Amazon |
| Listed scope domain | amazon.ca |
| Test date | 2026-09-25 08:24 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 5, Info: 8)

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
| 12 | info | CT1 | 109 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 13 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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

### 12. [INFO] 109 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.app.social.amazon.ca, api.social.amazon.ca, app.social.amazon.ca, help.amazon.ca, internal.campfire.amazon.ca, shop.social.amazon.ca, sophap.beta.gql.music.amazon.ca, support.amazon.ca
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 13. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: api.app.social.amazon.ca; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "amazon.ca",
  "dns": {
    "a": [
      "98.87.170.205",
      "98.82.155.12",
      "98.87.171.159"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "amazon-smtp.amazon.com (pref 10)"
    ],
    "ns": [
      "ns-1561.awsdns-03.co.uk.",
      "ns-1036.awsdns-01.org.",
      "ns-520.awsdns-01.net.",
      "ns-52.awsdns-06.com."
    ],
    "spf": [
      "uber-domain-verification=7a35217f-6956-41a0-be5c-a28ea2646964",
      "sending_domain229492=82f7d92f23b48fbe1e1a03ef83cb5a33aab6ffcbfc94faa5dccb681d9e488903",
      "uber-domain-verification=01e9f567-7b84-45dd-9326-53992a028b40",
      "sending_domain608861=78ca61d8b9a7c1a753b6770dffea9e6eb4ce681513fec5c35638f1c81bd375cf",
      "sending_domain229492=8fc1e4db25ccac36897136580c51327bbe8a5256582e84a7bb2f64c4453383e0",
      "uber-domain-verification=0ddb4c64-175c-4e7a-8a7a-f552034222e8",
      "canva-site-verification=o1N9Yacy_Q9Kl0710BHpzw",
      "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbDvoGpRaIwj/tgPH",
      "docker-verification=749d27fa-18f7-4933-bef5-ed333f53556b",
      "uber-domain-verification=72ffdffb-d431-452c-932e-cd1030d1eb46",
      "v=spf1 include:amazon.com -all",
      "box-domain-verification=ffea95cd0e0d61c302198367155b07e74fd534fa1d867662dc9bf9969b6f535d",
      "sending_domain608861=fd6e4e5c8ac1742d0173098538a216ea73818f1f4f8c4094ba26303da6007ee6",
      "sending_domain1003771=0212f52e68db5e2cffad95c587e13549995e8dcf28629ac3c8d1b3ea0dbd2fee",
      "facebook-domain-verification=ps3oomhw99zvbl2f2j55zgjmwgksys",
      "liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo",
      "spf2.0/pra include:amazon.com -all",
      "google-site-verification=L1r_iURvVl8iMPeesmTnJMjir81-5xK_8r-SOS9vL3w",
      "google-site-verification=LivBRhp5Uf9LRKW4XC5YEaexYZPWZw0GVN7qWtMT-1o",
      "uber-domain-verification=5f5cc242-4dbe-4871-b726-bbbe085ff053",
      "sending_domain1003771=d8fbb81d5f6de3bfb9d5cf396770c228dd3ada847b97e2bc12700deea6d90c87"
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
    "subject": "commonName=*.bx.peg.a2z.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Jun 27 00:00:00 2026 GMT",
    "notAfter": "Jan 10 23:59:59 2027 GMT",
    "san": [
      "*.bx.peg.a2z.com",
      "arcus-www.amazon.ca",
      "amazon.ca",
      "edgeflow-dp.aero.3a3674792-frontier.amazon.ca",
      "edgeflow.aero.3a3674792-frontier.amazon.ca",
      "www.amazon.ca",
      "p-yo-www-amazon-ca-kalias.amazon.ca",
      "p-y3-www-amazon-ca-kalias.amazon.ca",
      "origin-www.amazon.ca",
      "p-nt-www-amazon-ca-kalias.amazon.ca"
    ],
    "days_left": 107,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "98.87.170.205",
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
      "origin": "https://sub.amazon.ca",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://amazon.ca/"
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
    "count": 109,
    "notable": [
      "api.app.social.amazon.ca",
      "api.social.amazon.ca",
      "app.social.amazon.ca",
      "help.amazon.ca",
      "internal.campfire.amazon.ca",
      "shop.social.amazon.ca",
      "sophap.beta.gql.music.amazon.ca",
      "support.amazon.ca"
    ],
    "sample": [
      "a9g-api.amazon.ca",
      "aam-ca.amazon.ca",
      "aam.amazon.ca",
      "abintegrations.amazon.ca",
      "accelerator.amazon.ca",
      "account.kep.amazon.ca",
      "aero-edgeonly-test1.amazon.ca",
      "aero-standard-testing77-exp2.amazon.ca",
      "aero-standard-testing78-exp2.amazon.ca",
      "aerostandard-test-amadarap.amazon.ca",
      "alexa-skills-beta-eu.amazon.ca",
      "alexa-skills-na.amazon.ca",
      "alexa-skills.amazon.ca",
      "alexaskills.amazon.ca",
      "amazon.ca",
      "amg.amazon.ca",
      "ams.amazon.ca",
      "answergroups.amazon.ca",
      "api-amazondevices.amazon.ca",
      "api-key.amazon.ca"
    ],
    "dangling": [
      "api.app.social.amazon.ca"
    ]
  },
  "elapsed_s": 126.5,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
