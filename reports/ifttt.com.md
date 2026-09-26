# Security Audit Report — ifttt.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ifttt.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ifttt.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 0, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |

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

## Evidence (raw response observations)

```json
{
  "domain": "ifttt.com",
  "dns": {
    "a": [
      "3.169.121.105",
      "3.169.121.27",
      "3.169.121.2",
      "3.169.121.41"
    ],
    "aaaa": [
      "2600:9000:284c:ac00:1:b1c6:9e40:93a1",
      "2600:9000:284c:9400:1:b1c6:9e40:93a1",
      "2600:9000:284c:a00:1:b1c6:9e40:93a1",
      "2600:9000:284c:e400:1:b1c6:9e40:93a1",
      "2600:9000:284c:da00:1:b1c6:9e40:93a1",
      "2600:9000:284c:2200:1:b1c6:9e40:93a1",
      "2600:9000:284c:6c00:1:b1c6:9e40:93a1",
      "2600:9000:284c:4400:1:b1c6:9e40:93a1"
    ],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 10)",
      "aspmx2.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-676.awsdns-20.net.",
      "ns-425.awsdns-53.com.",
      "ns-1400.awsdns-47.org.",
      "ns-1614.awsdns-09.co.uk."
    ],
    "spf": [
      "google-site-verification=VdD3iT9gG8si3Zu4-crc2cMxN3b3oiRHtFcEAiDwTLc",
      "facebook-domain-verification=2gbh6mjor9buxlzajjq1hjbnksveuo",
      "v=MCPv1; k=ed25519; p=shhg+Sx/4D+wFvY1jwECmtgaGtpfAC5UDl0mb+mhdNg=",
      "v=spf1 include:sendgrid.net include:_spf.google.com include:customeriomail.com include:mail.zendesk.com include:stspg-customer.com -all",
      "edca106a3d3b474e87b5e47c25f607ec",
      "a774vnn3gtgp35cvtd31idrcug",
      "qrql38igvi0ce4abfi3on0vvke",
      "google-site-verification=LaHtMW5vokuLBZBVhajjw-NS3aQbRMOOz92B-RM_4hQ",
      "pinterest-site-verification=8e6e3928621ee8deeaa774c7569bb607",
      "google-site-verification=sdwLeEbGkwDQnNef_ZybsYYO1nz4RksHjJlL4BFy97c",
      "openai-domain-verification=dv-owUo2sHFljJJv2dyVfHqW3bb",
      "stripe-verification=d9aecd16a51b8f74a32c270d11a6bce84470c737c9d1e1de696edbce60ea7b47",
      "have-i-been-pwned-verification=1931e44ce46fd205b3806eff20a8b416",
      "status-page-domain-verification=btfx82x3lwwg",
      "_globalsign-domain-verification=rRjaOlcgFhBuUq2_dp1lnClpS6rvXrnUtycKh8GTEH",
      "globalsign-domain-verification=2D384BE73AFA22F600E2F2FD71973C63",
      "MS=ms71593285",
      "hubspot-developer-verification=ODA3YjI3MGQtOTk1Ni00YzgxLWE2NjAtNzkyYjljZDU4MzVj"
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
    "days_left": 63,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.121.105",
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
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 42.4,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
