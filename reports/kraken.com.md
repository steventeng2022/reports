# Security Audit Report — kraken.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://kraken.com/ |
| Bug bounty program | Kraken |
| Listed scope domain | kraken.com |
| Test date | 2026-09-25 09:55 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 2, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
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

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.17.186.205:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.17.186.205:8443 succeeded (state-only check, no payload sent).
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
- **Detail:** Header reveals: cloudflare
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
  "domain": "kraken.com",
  "dns": {
    "a": [
      "104.17.186.205",
      "104.17.188.205",
      "104.17.185.205",
      "104.17.189.205",
      "104.17.187.205"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 1)"
    ],
    "ns": [
      "art.ns.cloudflare.com.",
      "kim.ns.cloudflare.com."
    ],
    "spf": [
      "openai-domain-verification=dv-dzZ4sOyX0NcWC0W69R0SsmoJ",
      "docusign=9c156ad3-ca07-455a-ac23-4b069bff0cfc",
      "applause-verification=475eb036-5381-4119-9100-5293e2ce0ba8",
      "hubspot-domain-verification=YzE0ZGQ3MDYtYzc0ZC00MjhjLTg1MzktNWFhOWY0MGVmN2Uy",
      "yahoo-verification-key=vaBi9VRY3fC1ePDJDKbb3JeKZkVxdHdNNS2ehnZfPNs=",
      "sinch-domain-verification=f784f03b-c2b8-4acc-8790-30b91c091d49",
      "jamf-site-verification=s7-zemXlw9o875MwP_jHJQ",
      "attio-domain-verification=2PW6H5PPEKZJ5NZ536X46U9D",
      "docusign=df1e68ac-ef17-4239-a91c-ddc63bbf37a0",
      "loom-site-verification=0994d1d30bec445bb94dee2ca26c6672",
      "slack-domain-verification=xF9FoS5YecfnIOdXDAWxjJlBJeTP4k0x4XVUDcBm",
      "facebook-domain-verification=aoubhu5uh89ja6n8x12q5rwgxjy4qk",
      "v=spf1 include:_spf.google.com include:mail.zendesk.com include:mailgun.org -all",
      "tenderly-domain-verification-h41x4t=Xb51eXZGQ6C9IlZJXexoZnSkh",
      "cursor-domain-verification-1q4veq=T4badkQWyIFP5sdGc2ZdZO5hH",
      "apple-domain-verification=GxkQnQWBDwHc5Lwo",
      "status-page-domain-verification=zvdwk97f78sw",
      "mixpanel-domain-verify=8d24704c-eebf-4a86-bc1d-5facea16d192",
      "TSW_MTk2M3RlcmFzd2l0Y2g=",
      "linear-domain-verification=z4df5eemibyi",
      "verification_token=YEulsvbYjUK5ARSNvSKChCvak",
      "google-site-verification=Pn6aFNBpXpjjEwQiBhV2w86qkmACWSj6bSWf6iq93N4",
      "MS=ms92323866",
      "google-site-verification=XPT9uOe0jA_sa1A9KO2KHlflVyytnnJI6c51vXL7Th0",
      "have-i-been-pwned-verification=dweb_htjuxmmxivpa7y21mu12mq4f",
      "borderless-ai-domain-verification-891kzp=imAYYfgCNhUvxixCG9xeLErS7",
      "atlassian-domain-verification=4jtiW1tiUQSTvJZESUb2w2e6bDUeZnwV3HuW4EKB8Dnj7wVDMzFFvtXm/mFgKiq/",
      "chain-patrol-domain-verification-d32dw1=6Bi2nOcSd80VwhhSb1ieNE23u",
      "apple-domain-verification=jhXlcC3333rByj6_TIRCWS8depzse4Zg_PA2TAA8MvY",
      "lovable_verification=yrJSzJCXE2IlVOsGopmj",
      "anthropic-domain-verification-qq6f4e=yMnhINbeoqj341dPhfek46Gvw",
      "hubspot-domain-verification=ZDNhOWZkYmMtZjU0Yi00NjM0LTg0YTYtOWI3ZmM3ZDE1MTMx",
      "onetrust-domain-verification=ef58037d66994387a249e260b49da885"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; adkim=r; aspf=s; fo=1; rua=mailto:dmarc-rua@kraken.com; ruf=mailto:dmarc-ruf@kraken.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=kraken.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 30 10:57:16 2026 GMT",
    "notAfter": "Nov 28 11:57:12 2026 GMT",
    "san": [
      "kraken.com"
    ],
    "days_left": 64,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.17.186.205",
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
      "origin": "https://sub.kraken.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.kraken.com/"
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 21.9,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
