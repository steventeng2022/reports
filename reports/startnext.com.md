# Security Audit Report — startnext.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://startnext.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | startnext.com |
| Test date | 2026-09-25 10:19 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.66.135.76:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.66.135.76:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "startnext.com",
  "dns": {
    "a": [
      "172.66.135.76",
      "172.66.138.150"
    ],
    "aaaa": [
      "2606:4700:10::ac42:8a96",
      "2606:4700:10::ac42:874c"
    ],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "jocelyn.ns.cloudflare.com.",
      "will.ns.cloudflare.com."
    ],
    "spf": [
      "ahrefs-site-verification_a3ef10fe6feb196e637f47c659a513b57e8451002a446786c463e76edfdc36ed",
      "sipgate_domain_verification=ocgEkVPKtc65nr5iq812hD3KjmbZFsVN",
      "v=spf1 include:spf.mailjet.com include:spf1.stripe.com include:_spf.google.com mx ~all",
      "Sendinblue-code:f353cef9d786bf84e5c651a6c36eabe1",
      "google-site-verification=1sAqiWWlwgiOXvDGSL_I4U17ntLCTVOx7dEbvnR9LFQ",
      "canva-site-verification=Lef60elp9_zJViARgO1t_Q",
      "zapier-domain-verification-challenge=09073caa-9f62-43e0-8e6c-4f3d4a71ff0a",
      "apple-domain-verification=EFkPQxPpmNH3P9qq",
      "stripe-verification=10777e885e2161e55049d4bb5b7f8b2daeab406e486d229fcccf85c5960d924f",
      "figma-domain-verification=0f0367ec6cadf1d90abb1acf60f4d9eb0aeada705ee4c551606ba0479e7af19f-1769525845",
      "openai-domain-verification=dv-8ddqCEpCTKHtOHpVBDDRvyBP",
      "anthropic-domain-verification-afn3zm=kLvCbR5sjNLzPmTZq2GkNL5wp",
      "loaderio=ddeb6ac1a8a34860bcd9860ab8197ac6",
      "facebook-domain-verification=stvicj5365sof2wwqhjvmfx4gj94qq",
      "google-site-verification=iLJXA2QAMVvQ0ygkJP5gfwoZckSWP2ScE6DfDK_WDQo",
      "sdfcdef4gfeqfdafr3fdeqfdef",
      "lovable_verification=cdfc6ea695bda4007160736f9b3c884d431081ad3e971b8558f4d038da3fd8b4",
      "notion-domain-verification=WSNIySxByulDNwhZwtDjy9216rTsi81KLbLZuNGAS6A",
      "1password-site-verification=3CHE4U4RBNBC3KMOD33ZBSTPBQ",
      "postman-domain-verification=804e758eb395e1f9631a5a6ffcdb1213ed51ad4fbafcb0a4e78234bde9381b48586dcf6468efe8d61cec1b0205bfa095378c40393ecf6f3d0cbb1286b989e5cd",
      "status-page-domain-verification=v166389cy5dz",
      "hcp-domain-verification=60743923ec7473d8ae8b1adb950803da7ced6b57f812ca059c6814600de88f8e",
      "jetbrains-domain-verification=4tyrq5pfov7ujkxnj7y60r8ya"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:3fe3005f1fa8445381ae617deb23b808@dmarc-reports.cloudflare.net,mailto:re+srhio0nnmwp@dmarc.postmarkapp.com; sp=reject; aspf=r;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=startnext.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug  5 09:06:41 2026 GMT",
    "notAfter": "Nov  3 10:06:37 2026 GMT",
    "san": [
      "startnext.com",
      "mcp.startnext.com",
      "*.mcp.startnext.com"
    ],
    "days_left": 38,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.66.135.76",
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
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.startnext.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://startnext.com/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 42.1,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
