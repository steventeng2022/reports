# Security Audit Report — quora.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://quora.com/ |
| Bug bounty program | Quora |
| Listed scope domain | quora.com |
| Test date | 2026-09-25 10:11 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "quora.com",
  "dns": {
    "a": [
      "100.57.220.137",
      "18.208.80.151",
      "54.156.213.24"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-673.awsdns-20.net.",
      "ns-1143.awsdns-14.org.",
      "ns-1573.awsdns-04.co.uk.",
      "ns-344.awsdns-43.com."
    ],
    "spf": [
      "loom-site-verification=fbb3540487864ef086ceb33d6e93dc1b",
      "docusign=ed3b177c-9f9e-46b8-822f-378104f0e937",
      "globalsign-domain-verification=EnPHtt5EmnAS8ylIFlfJ0gcCPsrQy7SBNgoFOAHsIG",
      "anthropic-domain-verification-q9zk8w=qQTJ0XHnIN5d01dwaT5JiUjqD",
      "notion-domain-verification=XZ50Z8vAqIAKtBJKdHc2vNjkyEDlfL8zQVdTrl5rAsw",
      "google-site-verification=YHVWrk9up0QuAIkeCEeZ6J7ty5jDoKwX1yNW_GST5Zg",
      "google-site-verification=G3Xtneu_M6gnP9CFQgSCarSMCLhl2F1v1erLvqD_DTU",
      "google-site-verification=clhTdgpCJ96li3EYCyeaXOrE4iREb4h0qAKpZCiRhjA",
      "google-site-verification=tJbVk5zKwtko2UmH7oTIh6K_gk5PDHa6yMr33yhC23s",
      "d3o4sganq6g12y.cloudfront.net",
      "google-site-verification=dPlPDM4NC9Cbm9HYrvs78idrWsw7ImV_1dPbLoYQmyY",
      "google-site-verification=zFnSLKb0PqvlMBreKFyJ9xq2RXL3UuhATVjFpoUSpvc",
      "google-site-verification=ZJilmJEnKdQ0PZQCWgmvTVHKvWcFPfI61-5J4aoYiBM",
      "anthropic-domain-verification-ff87rw=roOVmHA9vsF5YBzqavhqZRnUp",
      "v=spf1 include:_spf1.quora.com include:_spf2.quora.com include:_spf.google.com include:mail.zendesk.com include:mailsenders.netsuite.com include:mktomail.com include:_spf.salesforce.com ~all",
      "globalsign-domain-verification=FnXWfFjPqReOGiIH8ITAbUasqKxnix6ftvTUzPOKHF",
      "openai-domain-verification=dv-PBdVIYKdEhZODJLXNZPwlxrS",
      "MS=ms41108016",
      "_globalsign-domain-verification=EGXYWFCTQynvOf5IBle5NjMEbKo9PBQaeH9mnr_Faj",
      "turbopuffer-domain-verification-dbezx6=X1B8vvtffA2f2IlvINwKRjYd8",
      "google-site-verification=Ds6XsFtKHEpL7_tJLe9dGv1H8-fOa8Uql7lXZdlTIOg",
      "jamf-site-verification=NG_yXXzmIUuroRjFeEjK-A"
    ],
    "dmarc": [
      "v=DMARC1; p=reject;rua=mailto:dmarc+rua@quora.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=quora.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR1",
    "notBefore": "Jul 29 06:08:46 2026 GMT",
    "notAfter": "Oct 27 06:08:45 2026 GMT",
    "san": [
      "quora.com",
      "*.quora.com",
      "*.www.quora.com",
      "*.tch.quora.com",
      "*.tch.www.quora.com",
      "qr.ae",
      "*.qr.ae",
      "fs.quoracdn.net",
      "*.fs.quoracdn.net",
      "cf2.quoracdn.net",
      "*.cf2.quoracdn.net"
    ],
    "days_left": 31,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "100.57.220.137",
    "open": []
  },
  "https": {
    "status": 308,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.quora.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 308,
    "location": "https://quora.com/"
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
  "elapsed_s": 40.4,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
