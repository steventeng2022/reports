# Security Audit Report — digitaltrends.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://digitaltrends.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | digitaltrends.com |
| Test date | 2026-09-25 17:50 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 4, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 13 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | info | CT1 | 23 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
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

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 13. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.digitaltrends.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 14. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 15. [INFO] 23 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: altis.staging.es.digitaltrends.com, altis.staging.www.digitaltrends.com, dev.es.digitaltrends.com, dev.www.digitaltrends.com, files.digitaltrends.com, staging.altis.digitaltrends.com, staging.es.digitaltrends.com, staging.www.digitaltrends.com, status.digitaltrends.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "digitaltrends.com",
  "dns": {
    "a": [
      "3.169.55.55",
      "3.169.55.28",
      "3.169.55.89",
      "3.169.55.39"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "digitaltrends-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns-1711.awsdns-21.co.uk.",
      "ns-78.awsdns-09.com.",
      "ns-666.awsdns-19.net.",
      "ns-1522.awsdns-62.org."
    ],
    "spf": [
      "google-site-verification=-MksWPwuf34sS1-oJvSzJIW9KsE7CskTBNvUJUs9zGU",
      "apple-domain-verification=ixKwVGxwE9TXeZ3F",
      "facebook-domain-verification=o9gokha6nwug1sltr4wj9wtcks2ro4",
      "tollbit-domain-verification=834a1886734f6bddd5015deaacc39c6e682c78b4e60db097b72da9aa949d693d",
      "atlassian-domain-verification=3UciTRhiPPalGnfMwEyifXMToIaV1gtpnmaMiUMu/9js/FnaCipcVQtCjIbTpoMk",
      "atlassian-domain-verification=fJAmOfQYHw3K7C1fuKa4yAi1JiFeMy47sg81/YoPzdpRty8zLVRGO0RsFE2nBJ8M",
      "fastly-domain-delegation-kjfbsakjhkjfakl-178404-2019-10-16",
      "MS=ms61723988",
      "google-site-verification=DGgmOFBDVC5ksJtU4Q5hyh9CvOXOdkNApwFou-IFOVo",
      "ahrefs-site-verification_9a82eef87599150f2c7cb0a33fd6674efaec660b67d411fe3aaed0db8e928d0d",
      "v=spf1 include:spf.protection.outlook.com include:spf.tipalti.com -all",
      "google-site-verification=nZ03eoxIbZX2vx96rqCcdtoGnh3s5YYKrTLrXSNsrBk",
      "google-site-verification=9UqhZ3_NAJ9h080POi3QF5x58xVh8Fh6ksz_7VTBhrA",
      "5HwOFRfvC6HJXoxZ0NSTFWTYRqxdotArg8062xyCJLY=",
      "uber-domain-verification=69ff25a9-2786-43e3-a501-el0bf2fcf5c6",
      "openai-domain-verification=dv-YGTwSC2FWeOKciA5bJnao9yN",
      "google-site-verification=LhEEOYALF-FSwQtsNYjY34HKhnDVrnDjf79R-jywnA8",
      "yandex-verification: d3d90a55ca899aa7",
      "MS=ms32022712",
      "google-site-verification=KwP_ps6K2dA_GqqH09sP6ZRPv71JHxnSBwoZ9uSyCgo",
      "0ed1fe018a398da5ca17fb44baa314e68a3dc33e5d",
      "google-gws-recovery-domain-verification=71417947",
      "anthropic-domain-verification-126xck=x61kgVFV21lGsbJaZccxJJXDS",
      "dropbox-domain-verification=9zrbo1ot31id",
      "ZOOM_verify_XXjQmpVqSESiHkuoW4HdGw",
      "_globalsign-domain-verification=Fw09cFhmPL_-Bfg6BV5_NkyDEkXJfmQd4uPViX560A"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:newsletter@digitaltrends.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=digitaltrends-prod.altis.cloud",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Nov 29 00:00:00 2025 GMT",
    "notAfter": "Dec 28 23:59:59 2026 GMT",
    "san": [
      "digitaltrends-prod.altis.cloud",
      "altis.www.21oak.com",
      "altis.www.happysprout.com",
      "www.pawtracks.com",
      "21oak.com",
      "altis.es.digitaltrends.com",
      "altis.www.digitaltrends.com",
      "themanual.com",
      "altis.www.toughjobs.com",
      "digitaltrends.com",
      "pawtracks.com",
      "happysprout.com",
      "www.toughjobs.com",
      "www.blissmark.com",
      "altis.www.themanual.com",
      "blissmark.com",
      "altis.www.pawtracks.com",
      "*.digitaltrends-prod.altis.cloud",
      "toughjobs.com",
      "www.digitaltrends.com",
      "newfolks.com",
      "es.digitaltrends.com",
      "altis.www.blissmark.com",
      "www.themanual.com",
      "www.happysprout.com",
      "altis.www.newfolks.com",
      "www.newfolks.com",
      "www.21oak.com"
    ],
    "days_left": 94,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.55.55",
    "open": []
  },
  "https": {
    "status": 405,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.digitaltrends.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://digitaltrends.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 405",
    "/redirect?next=https://evil-auditor.example/x -> 405",
    "/go?url=https://evil-auditor.example/x -> 405",
    "/url?url=https://evil-auditor.example/x -> 405"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 405,
    "/.git/config": 405,
    "/.env": 403,
    "/.htaccess": 405,
    "/wp-login.php": 405,
    "/phpmyadmin/index.php": 405,
    "/server-status": 405,
    "/api/": 405
  },
  "subdomains": {
    "source": "certspotter",
    "count": 23,
    "notable": [
      "altis.staging.es.digitaltrends.com",
      "altis.staging.www.digitaltrends.com",
      "dev.es.digitaltrends.com",
      "dev.www.digitaltrends.com",
      "files.digitaltrends.com",
      "staging.altis.digitaltrends.com",
      "staging.es.digitaltrends.com",
      "staging.www.digitaltrends.com",
      "status.digitaltrends.com"
    ],
    "sample": [
      "altis.es.digitaltrends.com",
      "altis.staging.es.digitaltrends.com",
      "altis.staging.www.digitaltrends.com",
      "altis.www.digitaltrends.com",
      "click.digitaltrends.com",
      "dev.es.digitaltrends.com",
      "dev.www.digitaltrends.com",
      "digitaltrends.com",
      "elinkeb3.digitaltrends.com",
      "es.digitaltrends.com",
      "explore.digitaltrends.com",
      "files.digitaltrends.com",
      "guide.digitaltrends.com",
      "phluant.digitaltrends.com",
      "results.digitaltrends.com",
      "rs-stripe.digitaltrends.com",
      "sli.digitaltrends.com",
      "staging.altis.digitaltrends.com",
      "staging.es.digitaltrends.com",
      "staging.www.digitaltrends.com"
    ]
  },
  "elapsed_s": 6.1,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
