# Security Audit Report — khanacademy.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://khanacademy.org/ |
| Bug bounty program | Khan Academy |
| Listed scope domain | khanacademy.org |
| Test date | 2026-09-25 09:55 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

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

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
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
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "khanacademy.org",
  "dns": {
    "a": [
      "65.9.180.8",
      "65.9.180.126",
      "65.9.180.53",
      "65.9.180.111"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 10)",
      "aspmx3.googlemail.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-1664.awsdns-16.co.uk.",
      "ns-125.awsdns-15.com.",
      "ns-1489.awsdns-58.org.",
      "ns-798.awsdns-35.net."
    ],
    "spf": [
      "globalsign-domain-verification=qV_5Us2mt6FO1Ig5hnG4kYHESYAxuH5-qZ0cRXC-Ig",
      "MS=ms10049948",
      "google-site-verification=7kTMmLFa8kfzTFffAv659zZAhSvDX5lqnB_yuST-xLY",
      "openai-domain-verification=dv-E4EGw5ZIgYd9B3mwA3dPV5zY",
      "spf2.0/pra include:_spf.google.com include:sendgrid.net include:aspmx.sailthru.com -all",
      "_globalsign-domain-verification=Prrz12gznJzJiHaajX3CnPfpqK6hhLae0miMSZ_BGa",
      "facebook-domain-verification=8kvuco8ljlv8t1aedswjypctrp1pk3",
      "google-site-verification=JML6gcy7DbE1dA3JB9W4O6EB9uQ8bpOlJTyniVCgd-o",
      "yahoo-verification-key=h5B5VELNOFcyiRDJQWEiNChg+SeClI9Bk9k9daiRPR4=",
      "google-site-verification=sHrvDlgokhtbjBWsn8Dhu616EFRRv8GD0C1AU4_1gl4",
      "_globalsign-domain-verification=Ca9ol7KyPTrPtyGjL1BqGx_wv6SymozDmCXhHJveUr",
      "onetrust-domain-verification=4bc2331ed4d24c81b7be278e6e1fb58b",
      "ZOOM_verify_G7FwqtyEKLkoQGhA3ifQq5",
      "cl_verification=a568671a-6112-4bc5-997d-1f06d8389b2e",
      "v=spf1 include:_spf.google.com include:sendgrid.net include:aspmx.sailthru.com include:mail.zendesk.com exists:%{i}._spf.mta.salesforce.com include:mg-spf.greenhouse.io -all",
      "google-site-verification=SprWzGYoIdXdFrUCSyBhXJtHzFjE8FAQNlTamgKenhU",
      "anthropic-domain-verification-4va7p1=Uuz4j8MkpGFjBjYBqvNGNuK46",
      "hibp-verify=dweb_9nibj6s7woei7t5h43qd3yni",
      "apple-domain-verification=FBF7Yx9o3htFHZ7m",
      "botify-site-verification=sGRcFNKzIkHzx1jtsQ7YkiT8hgWB6RiU",
      "google-site-verification=Jiabx8hC-zV0E8-hAj40dHCY_oWNIvfqkNe7VFnGbCs",
      "google-site-verification=y1w1HGdtmQcg92Uy4JtubYkFtDDshCwmDXTFCgjpr-Y",
      "stripe-verification=332820F9A5BCCCACBF2F5D8636496EB723C4062C9B878B8BAB77E99A2522E947",
      "canva-site-verification=JW5MeXNqA7ezvjIRgLOPaQ",
      "google-site-verification=BUF9CkP4-zm7sN2rDSq6NGRiEkrvvh2k3UdQxwSusrU",
      "cursor-domain-verification-dc9ngn=XEN4zLZD2K4p5yMB2JFUNxGIk",
      "_globalsign-domain-verification=e70UZqvudGByIeilV8oO0gubBZi0P7QLakTxKub-zS"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-reports@khanacademy.org; ruf=mailto:dmarc-reports@khanacademy.org"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=khanacademy.org",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Nov 11 00:00:00 2025 GMT",
    "notAfter": "Dec 10 23:59:59 2026 GMT",
    "san": [
      "khanacademy.org",
      "salkhan.com",
      "www.youcanlearnanything.org",
      "www.conacademy.com",
      "es.pixarinabox.org",
      "www.kahnacademy.com",
      "pt.pixarinabox.com",
      "youcanlearnanything.org",
      "conacademy.com",
      "pixarinabox.com",
      "www.salkhan.com",
      "camp.khankids.org",
      "www.khanacademy.es",
      "conacademy.org",
      "www.pixarinabox.org",
      "kahnacademy.org",
      "www.khankids.org",
      "sendgrid.khanacademy.org",
      "kasandbox.org",
      "www.khanacademy.com",
      "es.pixarinabox.com",
      "khanacademy.com.br",
      "khanacademy.com",
      "khanacademy.es",
      "www.conacademy.org",
      "pt.pixarinabox.org",
      "www.kahnacademy.org",
      "pixarinabox.org",
      "khan.co",
      "khankids.org",
      "www.khankids.com",
      "www.pixarinabox.com",
      "khankids.com",
      "kahnacademy.com",
      "ycla.khanacademy.org"
    ],
    "days_left": 76,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "65.9.180.8",
    "open": []
  },
  "https": {
    "status": 308,
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
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.khanacademy.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 308,
    "location": "https://www.khanacademy.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 308",
    "/redirect?next=https://evil-auditor.example/x -> 308",
    "/go?url=https://evil-auditor.example/x -> 308",
    "/url?url=https://evil-auditor.example/x -> 308"
  ],
  "paths": {
    "/robots.txt": 308,
    "/sitemap.xml": 308,
    "/.well-known/security.txt": 308,
    "/security.txt": 308,
    "/.git/HEAD": 308,
    "/.git/config": 308,
    "/.env": 308,
    "/.htaccess": 308,
    "/wp-login.php": 308,
    "/phpmyadmin/index.php": 308,
    "/server-status": 308,
    "/api/": 308
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 21.3,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
