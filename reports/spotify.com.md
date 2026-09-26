# Security Audit Report — spotify.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://spotify.com/ |
| Bug bounty program | Spotify |
| Listed scope domain | spotify.com |
| Test date | 2026-09-25 10:18 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 2, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
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
- **Detail:** Detected: Server: envoy
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000, h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Header reveals: envoy
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
  "domain": "spotify.com",
  "dns": {
    "a": [
      "35.186.224.24"
    ],
    "aaaa": [
      "2600:1901:1:7c5::"
    ],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "aspmx4.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)",
      "aspmx5.googlemail.com (pref 10)"
    ],
    "ns": [
      "ns-cloud-a1.googledomains.com.",
      "ns-cloud-a2.googledomains.com.",
      "ns-cloud-a3.googledomains.com.",
      "ns-cloud-a4.googledomains.com.",
      "dns1.p07.nsone.net."
    ],
    "spf": [
      "docker-verification=82f3553a-fb50-4d4e-9607-8a8079ee354f",
      "google-site-verification=uD4f4k01lFWX3qwVbqnVaJg8atpKgAgc-_RYcyT3ofU",
      "jamf-site-verification=1kKxrm0glhWvrA0YiABH_w",
      "atlassian-sending-domain-verification=d90f2e0c-fa57-43b6-910f-065cc4d6a0e3",
      "tiktok-developers-site-verification=pZNawVY3o5Ma80MRCC6Fref1NiLzuEVU",
      "google-site-verification=ESiNWockZgSgTPSsrsAdMX9afsj2-_8504nQ0qIHkDA",
      "tiktok-developers-site-verification=98xFqMKsOJ51nNJpUCGPGbo7m17gtf7f",
      "loom-site-verification=3ee9ca8c2df34d08abbb7be5185bc768",
      "reachdesk-verification=v0DuUrKxORfyqxIOMkJm57GlQtvaAv0watqt7x7ylMN21LAHqR6dEhUpSxOp7DCh",
      "parallels-domain-verification=7bb3a358f26f4e23a5077648266570c873182a57d6d44e47a55ef6cf72cdb470",
      "apple-domain-verification=Dxae2sKJD2O5TKGK",
      "MS=ms38184034",
      "tiktok-developers-site-verification=ttGXJxgq1HQKquomgiljzFq53uoLHcUC",
      "vmware-cloud-verification-dab4c35d-1819-4431-add3-d3c382ee32bc",
      "onetrust-domain-verification=508849d40e2b4b8fba2b7eaf84f1bddc",
      "openai-domain-verification=dv-VNYvLsJIttFvRz7ymxFgjrPC",
      "cursor-domain-verification-985xgr=7ROYkkLIfunrK2GtW0spMGDNw",
      "liveramp-site-verification=IAXPTLlWofr4aaKtwVqirrHvOqUMiXnaMW8WMmuz1v0",
      "windsurf-verification=LRBAV_kH3G5aleY1GIc1jMUg_8iBpigIm2qYF00bRps=",
      "notion-domain-verification=AqUDuql68X5rQ1qLwho6huUjf4QteXZlyvTIKS1txnq",
      "yahoo-verification-key=bdudmGyddArwRiVafgItrfYq8nrhd5vzNZ7Ik/G0ILM=",
      "_anz60jg9dhixqlmcv20ntnooz9m0k8x",
      "anthropic-domain-verification-mqtmtz=BSac9xfxvigNt4Ralt2KPkt1V",
      "v=spf1 ip4:80.76.146.172 ip4:80.76.146.173 include:_spf.google.com include:servers.mcsv.net include:_spf.salesforce.com include:_spf.netigate.se include:21894833.spf06.hubspotemail.net ~all",
      "google-site-verification=0wmxUE7T2OWPhtwjco6oCyqqbYgtosjQdywAr4G4kU0",
      "facebook-domain-verification=qyrvuca7h4s7wevhzbprtt3tdyyhf1",
      "cloudflare_dashboard_sso=19cd522a4fc20281209f03663d34ee76",
      "status-page-domain-verification=wq4jns7ydgbb",
      "have-i-been-pwned-verification=33b7ae688099ee8cca63259b769a0ea8",
      "facebook-domain-verification=wtgn9pdvjdhs21j9gz6knsnpkafvs5",
      "google-site-verification=ehIHBRyAOKdOfUyw_ONXT0TMuUsdk1gDGSYfk8YhRgw",
      "wiz-domain-verification=370862886b04dfa626d54d2c4cc955174c6f3164a104a85d725ae5ece72ea3ef",
      "atlassian-domain-verification=1My5WsxLluUY8uIjgbLs4MY3ySFp32k9aYNW2IR4ihM64k58CxpFnB5R9SEiJAnR",
      "google-site-verification=buTP-BbGUoP8lPntqskvSbeS68M4PDoIFkiUtQEA5n8",
      "zapier-domain-verification-challenge=db8a0b98-bb6a-4f84-a699-344dc23fef3b"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; fo=1; rf=afrf; rua=mailto:6jxge2ly@ag.eu.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=SE, localityName=Stockholm, organizationName=Spotify AB, commonName=*.spotify.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jul  9 00:00:00 2026 GMT",
    "notAfter": "Jan 23 23:59:59 2027 GMT",
    "san": [
      "*.spotify.com",
      "spotify.com"
    ],
    "days_left": 120,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "35.186.224.24",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: envoy"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.spotify.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.spotify.com/"
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
  "elapsed_s": 20.5,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
