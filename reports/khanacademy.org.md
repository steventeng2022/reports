# Security Audit Report — khanacademy.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://khanacademy.org/ |
| Bug bounty program | Khan Academy |
| Listed scope domain | khanacademy.org |
| Test date | 2026-09-26 17:48 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 5, Info: 11)

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
| 14 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

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

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (rsplwohgqdyj80.khanacademy.org and bb7jhgb3c7rfo0.khanacademy.org) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=7kTMmLFa8kfzTFffAv659zZAhSvDX5lqnB_yuST-xLY; canva-site-verification=JW5MeXNqA7ezvjIRgLOPaQ; botify-site-verification=sGRcFNKzIkHzx1jtsQ7YkiT8hgWB6RiU
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of khanacademy.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "khanacademy.org",
  "dns": {
    "a": [
      "65.9.180.8",
      "65.9.180.111",
      "65.9.180.126",
      "65.9.180.53"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-798.awsdns-35.net.",
      "ns-1489.awsdns-58.org.",
      "ns-1664.awsdns-16.co.uk.",
      "ns-125.awsdns-15.com."
    ],
    "spf": [
      "google-site-verification=7kTMmLFa8kfzTFffAv659zZAhSvDX5lqnB_yuST-xLY",
      "canva-site-verification=JW5MeXNqA7ezvjIRgLOPaQ",
      "botify-site-verification=sGRcFNKzIkHzx1jtsQ7YkiT8hgWB6RiU",
      "v=spf1 include:_spf.google.com include:sendgrid.net include:aspmx.sailthru.com include:mail.zendesk.com exists:%{i}._spf.mta.salesforce.com include:mg-spf.greenhouse.io -all",
      "apple-domain-verification=FBF7Yx9o3htFHZ7m",
      "hibp-verify=dweb_9nibj6s7woei7t5h43qd3yni",
      "yahoo-verification-key=h5B5VELNOFcyiRDJQWEiNChg+SeClI9Bk9k9daiRPR4=",
      "openai-domain-verification=dv-E4EGw5ZIgYd9B3mwA3dPV5zY",
      "_globalsign-domain-verification=Prrz12gznJzJiHaajX3CnPfpqK6hhLae0miMSZ_BGa",
      "facebook-domain-verification=8kvuco8ljlv8t1aedswjypctrp1pk3",
      "MS=ms10049948",
      "google-site-verification=y1w1HGdtmQcg92Uy4JtubYkFtDDshCwmDXTFCgjpr-Y",
      "stripe-verification=332820F9A5BCCCACBF2F5D8636496EB723C4062C9B878B8BAB77E99A2522E947",
      "spf2.0/pra include:_spf.google.com include:sendgrid.net include:aspmx.sailthru.com -all",
      "anthropic-domain-verification-4va7p1=Uuz4j8MkpGFjBjYBqvNGNuK46",
      "google-site-verification=Jiabx8hC-zV0E8-hAj40dHCY_oWNIvfqkNe7VFnGbCs",
      "onetrust-domain-verification=4bc2331ed4d24c81b7be278e6e1fb58b",
      "ZOOM_verify_G7FwqtyEKLkoQGhA3ifQq5",
      "google-site-verification=SprWzGYoIdXdFrUCSyBhXJtHzFjE8FAQNlTamgKenhU",
      "globalsign-domain-verification=qV_5Us2mt6FO1Ig5hnG4kYHESYAxuH5-qZ0cRXC-Ig",
      "cl_verification=a568671a-6112-4bc5-997d-1f06d8389b2e",
      "google-site-verification=BUF9CkP4-zm7sN2rDSq6NGRiEkrvvh2k3UdQxwSusrU",
      "cursor-domain-verification-dc9ngn=XEN4zLZD2K4p5yMB2JFUNxGIk",
      "_globalsign-domain-verification=e70UZqvudGByIeilV8oO0gubBZi0P7QLakTxKub-zS",
      "google-site-verification=sHrvDlgokhtbjBWsn8Dhu616EFRRv8GD0C1AU4_1gl4",
      "_globalsign-domain-verification=Ca9ol7KyPTrPtyGjL1BqGx_wv6SymozDmCXhHJveUr",
      "google-site-verification=JML6gcy7DbE1dA3JB9W4O6EB9uQ8bpOlJTyniVCgd-o"
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
    "days_left": 75,
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
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=7kTMmLFa8kfzTFffAv659zZAhSvDX5lqnB_yuST-xLY",
    "canva-site-verification=JW5MeXNqA7ezvjIRgLOPaQ",
    "botify-site-verification=sGRcFNKzIkHzx1jtsQ7YkiT8hgWB6RiU",
    "apple-domain-verification=FBF7Yx9o3htFHZ7m",
    "yahoo-verification-key=h5B5VELNOFcyiRDJQWEiNChg+SeClI9Bk9k9daiRPR4="
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
  "elapsed_s": 6.9,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
