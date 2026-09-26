# Security Audit Report — mashable.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mashable.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | mashable.com |
| Test date | 2026-09-25 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 4, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
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
- **Detail:** TCP connect to 172.64.145.239:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.145.239:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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
  "domain": "mashable.com",
  "dns": {
    "a": [
      "172.64.145.239",
      "104.18.42.17"
    ],
    "aaaa": [
      "2606:4700:440b::ac40:91ef",
      "2a06:98c1:3108::6812:2a11"
    ],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 50)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 40)",
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "melinda.ns.cloudflare.com.",
      "stan.ns.cloudflare.com."
    ],
    "spf": [
      "atlassian-domain-verification=kQFG/X7fUsfUDY23M1nY9V96UTPIKoWZT6X2VBnCL9xU3reVLExHilAHDSEYR9wT",
      "amazonses:Z5QNPJ5iPN0Mq3jLqd7VUtga9VuNpdaNc905BGCARiw=",
      "figma-domain-verification=4f7cdfa45ca39f617dd7ba7b165e1bfd5e9b5e1ec18b849c6098dfdc4a4cfa64-1740511309",
      "google-site-verification=glsA5aZxGHaju0Dgibt_UjPIRrL-ZSK6aooxg8pIVEs",
      "v=spf1 ip4:174.143.231.161/28 ip4:166.78.216.65/29 ip4:75.126.29.138 include:amazonses.com include:aspmx.sailthru.com include:_spf.google.com ~all",
      "atlassian-domain-verification=2SzYnHY5kqS93yaRjqFeXQ06/c1FGYtUTDzZ/ESvHPhpX0UGQJ6kxrQTWfcvA1Ys",
      "onetrust-domain-verification=abc51c8aabd44eb59261c3dc7493e90d",
      "ZOOM_verify_PWk64Qrl1OtbGw7dRHJZBG",
      "google-site-verification=ov-5YzWCfMr-76FIRNui6JkuyGtdIENMfMgNOH-Ie-o",
      "docusign=97cf394b-a0d4-4801-a1a9-b1230063483a",
      "adobe-idp-site-verification=cd8dab640ab786a9457c8757f4188cd682dd687a694d1d9c251e9ef54140a0ec",
      "canva-site-verification=4hV0PUE1d_0DpT4Pz9lZhQ",
      "facebook-domain-verification=bjfgcbesl39drcl7v0nj6696d3l0io",
      "atlassian-domain-verification=ABvZicrYcNZS0ZlndVmOFMZ4fKr9B5cnu3MSodGE7e9OvfSk6/uJlgtbvJ29tMcl",
      "google-site-verification=OA9nqSHn-vz22Uzs4gPRH9i_iGw24VhWpwUUoZ84JZI",
      "atlassian-domain-verification=oargRKtWj/XDaHvz3KJHstsWDqU1X1CFoYqlDKWGEAZ2wrAaqNHo6HWl6Kzv6/gU",
      "include:_spf.emailcampaigns.net",
      "atlassian-domain-verification=QUsZX4LdPWTYZgx09JhShFot27EJnUl/5CyxXFsiGebXl2QD8Fh3zzfkYZJe42Ic",
      "cloudflare_dashboard_sso=b9207a4cf3f8f5e2aa07e4eff6887c88",
      "MS=ms71451316",
      "google-site-verification=STHgGGPVQNIXuc2PZD2zSjPJGhPZB9J4XbYSeSm0Rec",
      "apple-domain-verification=eBeUoxT2aLZiv4AM",
      "anthropic-domain-verification-8yhnd2=JjQ2U1PXjSD1fuv7AsTl9wL04",
      "tollbit-domain-verification=86ee66d1d40cb4b2733cb249aa97f31d9b2f25a05c55b40a04f8de1592793223",
      "knowbe4-site-verification=f8a0eecde40ecb172ead956570d9179c"
    ],
    "dmarc": [
      "v=DMARC1;p=quarantine;rua=mailto:088836b424@rua.easydmarc.us;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=mashable.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep  6 13:21:52 2026 GMT",
    "notAfter": "Dec  5 14:21:48 2026 GMT",
    "san": [
      "mashable.com",
      "*.mashable.com"
    ],
    "days_left": 70,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.64.145.239",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "Mashable"
  },
  "mixed_content": [
    "href=\"http://"
  ],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "mashable.com",
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
      "origin": "https://sub.mashable.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://mashable.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 5.5,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
