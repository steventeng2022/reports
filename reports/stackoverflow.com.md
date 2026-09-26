# Security Audit Report — stackoverflow.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://stackoverflow.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | stackoverflow.com |
| Test date | 2026-09-25 10:18 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 198.252.206.1:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 198.252.206.1:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "stackoverflow.com",
  "dns": {
    "a": [
      "198.252.206.1"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "sureena.ns.cloudflare.com.",
      "damian.ns.cloudflare.com."
    ],
    "spf": [
      "onetrust-domain-verification=0d9d67f856334905a54256085a5768b3",
      "google-site-verification=rdWtMbplKjbRHGr2dNONfwkqithlUvjr3u6i8QEz_mo",
      "apple-domain-verification=O9jlnJXAQ7sNSZqC",
      "adobe-idp-site-verification=25ba5203f3687c9cd6ee3223ee5de1528917828d1da3ebd3bd9a44094cbfc4ac",
      "ibmid=4e7cbbb3-5f12-40b4-96c7-5b064347b822",
      "anthropic-domain-verification-q70207=cKyy0llXkD10O4rDQpWz8tQ5K",
      "docker-verification=d65aee54-9091-4ceb-b792-61f5d5804050",
      "make-domain-verification=eec31159-f381-4f38-9d89-e59123dd023e",
      "work-os-domain-verification-43a3e0=GoDUTSc5MMjDaiIC3s5yRKqMD",
      "openai-domain-verification=dv-GLNufzbWDzAq0fDXHD6jxeCK",
      "atlassian-domain-verification=byLeZgl3MIcfOqwWuMhq8Fhr/1zem/jIaouJegvDZbBKUU5OqhwDjdpkyYg5CTzm",
      "google-site-verification=2Bi6SYw5skkRexdtdLPL2gpxeIhLxnYVqITVP9Htl3w",
      "cursor-domain-verification-sb0ayf=Pk6AyptQuTpzpcuSlfYGWloxv",
      "ZOOM_verify_AbkNwz5bBl0eurcDKyhhuk",
      "v=MCPv1; k=ed25519; p=VhBofO8RaYvTvHT7q5tTty+HQeCU8R6h5Y8k/sj20So=",
      "onetrust-domain-verification=e445562296a64c649ae3d520230b8c4c",
      "profound-domain-verification-5p599x=hWudYd2Du6WOYOod5ko9Rwnp8",
      "docusign=4262531d-29f4-4a62-9f33-ae9f66f5247b",
      "google-site-verification=o3EMam8yBGo1yEjyybIiZcOunGHOQKpo8JmOtp9n1BU",
      "MS=ms52592611",
      "google-site-verification=ctogLnZNAdc_CXq8yOhODMLpmugGynjxKecKHDz4oL8",
      "v=spf1 ip4:52.38.191.241 include:_spf.google.com include:mailgun.org include:sendgrid.net include:mail.zendesk.com include:spf.tipalti.com ~all"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-aggregates@stackoverflow.com; ruf=mailto:dmarc-forensics@stackoverflow.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=stackoverflow.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Aug 15 12:39:06 2026 GMT",
    "notAfter": "Nov 13 12:39:05 2026 GMT",
    "san": [
      "*.stackoverflow.com",
      "stackoverflow.com"
    ],
    "days_left": 49,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "198.252.206.1",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 429,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "stackoverflow.com",
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
      "origin": "https://sub.stackoverflow.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://stackoverflow.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 429",
    "/redirect?next=https://evil-auditor.example/x -> 429",
    "/go?url=https://evil-auditor.example/x -> 429",
    "/url?url=https://evil-auditor.example/x -> 429"
  ],
  "paths": {
    "/robots.txt": 418,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 429,
    "/security.txt": 429,
    "/.git/HEAD": 429,
    "/.git/config": 429,
    "/.env": 429,
    "/.htaccess": 429,
    "/wp-login.php": 429,
    "/phpmyadmin/index.php": 429,
    "/server-status": 429,
    "/api/": 429
  },
  "subdomains": {
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 42.2,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
