# Security Audit Report — amazon.fr

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://amazon.fr/ |
| Bug bounty program | Amazon |
| Listed scope domain | amazon.fr |
| Test date | 2026-09-25 08:30 UTC |
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
| 12 | info | CT1 | 132 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 12. [INFO] 132 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: beta.gql.music.amazon.fr, cloud.amazon.fr, help.amazon.fr, support.amazon.fr
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "amazon.fr",
  "dns": {
    "a": [
      "3.254.237.67",
      "3.254.236.66",
      "3.253.169.23"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "amazon-smtp.amazon.com (pref 10)"
    ],
    "ns": [
      "ns2.amzndns.com.",
      "ns1.amzndns.co.uk.",
      "ns2.amzndns.net.",
      "ns2.amzndns.co.uk.",
      "ns2.amzndns.org.",
      "ns1.amzndns.net.",
      "ns1.amzndns.com.",
      "ns1.amzndns.org."
    ],
    "spf": [
      "autodesk-domain-verification=N5Zg6KZwXQDo-pudDkME",
      "google-gws-recovery-domain-verification=68064248",
      "MS=ms18995963",
      "liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo",
      "sending_domain229492=583de145d75ff66143e88dca273460447d95061a4213307f4d320600a3c1dcaa",
      "google-gws-recovery-domain-verification=70440556",
      "MS=ms46743318",
      "spf2.0/pra include:spf.mandrillapp.com include:amazon.com -all",
      "v=spf1 include:spf.mandrillapp.com include:amazon.com -all",
      "sending_domain1003771=d9728424f2813de308b9887cb13c87f9400c6172e727dca7b3feca1cb4437055",
      "ZOOM_verify_uzXEpZoIQGsNdrlphjJ59I",
      "cisco-ci-domain-verification=13ba27e01f786cffd46142fb80e6f2ec6a8523fe86a66d591b101401dc4d6b8c",
      "sending_domain1003771=3267c0d73b632f4cc5acb58bc0f3b77915039677c23eb7d503d89928b10cbbe2",
      "adobe-idp-site-verification=b6bcd3e5aaffc63607c8bf75744d9a0d1febc50dd7f389428e2ae476c9ba8814",
      "box-domain-verification=ffea95cd0e0d61c302198367155b07e74fd534fa1d867662dc9bf9969b6f535d",
      "kahoot-domain-verification=b62357d8cf9c76c6d5bf6888b63b9f1a6a65ebb3755210709a16ce752b3253f6",
      "canva-site-verification=bFpVPinHHZos3PY6CD0Tbw",
      "google-site-verification=vmQPE7p4uYTNHVtaQmytT-CZayW8ruLXycMsEBl_kIo",
      "bluebeam-verification=aoc2ya9tkhh2drq1723kaba2yui1nd",
      "google-site-verification=U3inbmCLfS-MnCQvnNkeCB2aPKsmqeS9Ly54tfJJR50",
      "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbDvoGpRaIwj/tgPH",
      "cisco-ci-domain-verification=74d02efdae2201a6a42b1c6e1068a47e69dda71fbd4defef5a70e23d800da1fd",
      "sending_domain608861=cf2a0d867c19a529fea9d2246519da0b618b935a8d64efb744ea49ef76b52869",
      "google-site-verification=NkoFxShJGME_teW9sIj1QzZ7gbyG-HWJvLtFhIfqHnc",
      "facebook-domain-verification=pkqx4a7mquzleeunwoog6hv56rny8w",
      "docker-verification=64c0e1f7-ccdf-4192-8eaa-8eb129095d13",
      "sending_domain229492=5ff0ab96243078b774f045d24b65144988a46f4578e8c0116d7eb099b14cc13c",
      "sending_domain608861=73515280138a29820094c17699cd6051561cd16b1b60c732ed4860cad0b96480"
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
    "subject": "commonName=*.cz.peg.a2z.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Aug  4 00:00:00 2026 GMT",
    "notAfter": "Feb 17 23:59:59 2027 GMT",
    "san": [
      "*.cz.peg.a2z.com",
      "edgeflow.aero.f0c2e5164-frontier.amazon.fr",
      "p-nt-www-amazon-fr-kalias.amazon.fr",
      "edgeflow-dp.aero.f0c2e5164-frontier.amazon.fr",
      "www.amazon.fr",
      "p-y3-www-amazon-fr-kalias.amazon.fr",
      "amazon.fr",
      "p-yo-www-amazon-fr-kalias.amazon.fr",
      "origin-www.amazon.fr"
    ],
    "days_left": 145,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.254.237.67",
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
      "origin": "https://sub.amazon.fr",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://amazon.fr/"
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
    "count": 132,
    "notable": [
      "beta.gql.music.amazon.fr",
      "cloud.amazon.fr",
      "help.amazon.fr",
      "support.amazon.fr"
    ],
    "sample": [
      "aan.amazon.fr",
      "aax-eu.amazon.fr",
      "abintegrations.amazon.fr",
      "ablistswidgethorizonte.amazon.fr",
      "accelerator.amazon.fr",
      "account.kep.amazon.fr",
      "advantage.amazon.fr",
      "alexa-skills-beta-eu.amazon.fr",
      "alexa-skills-beta.amazon.fr",
      "alexa-skills-na.amazon.fr",
      "alexaanswers.amazon.fr",
      "amazon.fr",
      "amg.amazon.fr",
      "api-key.amazon.fr",
      "api-preprod.amazon.fr",
      "arcus-www.amazon.fr",
      "asmw.amazon.fr",
      "assistant.amazon.fr",
      "associates-blog.amazon.fr",
      "associates.amazon.fr"
    ]
  },
  "elapsed_s": 109.5,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
