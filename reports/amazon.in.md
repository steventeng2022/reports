# Security Audit Report — amazon.in

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://amazon.in/ |
| Bug bounty program | Amazon |
| Listed scope domain | amazon.in |
| Test date | 2026-09-25 08:31 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 4, Info: 8)

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
| 12 | info | CT1 | 120 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 12. [INFO] 120 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.eu-west-1.prod.proxy.live.amazon.in, beta.buywithamazon.amazon.in, beta.gql.music.amazon.in, docs.amazonpay.amazon.in, help.amazon.in, pay.amazon.in, support.amazon.in
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "amazon.in",
  "dns": {
    "a": [
      "3.253.170.100",
      "3.253.176.101",
      "3.253.168.43"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "amazon-smtp.amazon.com (pref 10)"
    ],
    "ns": [
      "ns1.amzndns.co.uk.",
      "ns2.amzndns.com.",
      "ns2.amzndns.co.uk.",
      "ns2.amzndns.net.",
      "ns1.amzndns.org.",
      "ns1.amzndns.com.",
      "ns1.amzndns.net.",
      "ns2.amzndns.org."
    ],
    "spf": [
      "spf2.0/pra include:amazon.com -all",
      "google-gws-recovery-domain-verification=70440648",
      "liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo",
      "kahoot-domain-verification=c1ef4a458d927fa9054ae24946b2228c246e07972ce6e8a8ad017acf06c434f4",
      "MS=ms27803002",
      "facebook-domain-verification=hgfnhz04meuxr62da6b00kwas2n4md",
      "MS=ms65650497",
      "google-site-verification=GsLI5kBVqu0oRPMAr-bFqvv3FRTlCiHyYQ2VUGDNwHM",
      "TS1760027",
      "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbDvoGpRaIwj/tgPH",
      "v=spf1 include:amazon.com -all",
      "google-site-verification=xTaP4clXFdYM8wMNQRgr5Ezb9b9STzHgq4tmVyZrDEI",
      "google-gws-recovery-domain-verification=69979608",
      "bluebeam-verification=nbh9t8rjoaej9iluzr8knu56ehfv84",
      "google-site-verification=ABRnURlPVtQRBIMqadgOhBTXsxY_HxEn04unYT9D0J4",
      "adobe-idp-site-verification=b6bcd3e5aaffc63607c8bf75744d9a0d1febc50dd7f389428e2ae476c9ba8814",
      "docker-verification=18325118-b0dc-40bd-81c5-d6aafedf278c",
      "google-site-verification=xibV-ooZgBwkpinWNuETXl-tasUI80Q4nxnNQVqE8cw",
      "canva-site-verification=hbDzfqg-Yto5mQswKAEatA"
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
    "subject": "commonName=*.cy.peg.a2z.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Aug 11 00:00:00 2026 GMT",
    "notAfter": "Feb 24 23:59:59 2027 GMT",
    "san": [
      "*.cy.peg.a2z.com",
      "www.amazon.co.in",
      "p-y3-www-amazon-in-kalias.amazon.in",
      "p-yo-www-amazon-in-kalias.amazon.in",
      "origin-www.amazon.in",
      "amazon.in",
      "edgeflow-dp.aero.c95e7e602-frontier.amazon.in",
      "amazon.co.in",
      "edgeflow.aero.c95e7e602-frontier.amazon.in",
      "p-nt-www-amazon-in-kalias.amazon.in",
      "www.amazon.in"
    ],
    "days_left": 152,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.253.170.100",
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
      "origin": "https://sub.amazon.in",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://amazon.in/"
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
    "count": 120,
    "notable": [
      "api.eu-west-1.prod.proxy.live.amazon.in",
      "beta.buywithamazon.amazon.in",
      "beta.gql.music.amazon.in",
      "docs.amazonpay.amazon.in",
      "help.amazon.in",
      "pay.amazon.in",
      "support.amazon.in"
    ],
    "sample": [
      "aam.amazon.in",
      "aan.amazon.in",
      "aax-eu.amazon.in",
      "abintegrations.amazon.in",
      "accelerator.amazon.in",
      "account-status.amazon.in",
      "account.kep.amazon.in",
      "al-eu-apiproxy.amazon.in",
      "alexa-skills-beta-eu.amazon.in",
      "alexa-skills-beta.amazon.in",
      "alexa-skills-na.amazon.in",
      "alexa-smart-nudge.amazon.in",
      "alm.amazon.in",
      "amazon.in",
      "amazonpay-insurance.amazon.in",
      "amazonpay-sandbox.amazon.in",
      "ams.amazon.in",
      "api.eu-west-1.prod.proxy.live.amazon.in",
      "arcus-www.amazon.in",
      "asmw.amazon.in"
    ]
  },
  "elapsed_s": 203.9,
  "rechecked": "2026-09-25 10:43 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
