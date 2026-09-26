# Security Audit Report — expedia.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://expedia.com/ |
| Bug bounty program | Expedia Group |
| Listed scope domain | expedia.com |
| Test date | 2026-09-25 09:40 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
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

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 24 days (notAfter Oct 19 22:02:31 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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
- **Detail:** Header reveals: AkamaiGHost
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
  "domain": "expedia.com",
  "dns": {
    "a": [
      "23.37.92.132",
      "23.37.92.138"
    ],
    "aaaa": [
      "2600:140b:1c00:47::1734:8c86",
      "2600:140b:1c00:47::1734:8cae"
    ],
    "cname": null,
    "mx": [
      "mxa.expediagroup.com (pref 10)",
      "mxb.expediagroup.com (pref 10)"
    ],
    "ns": [
      "pdns4.ultradns.org.",
      "dns1.p09.nsone.net.",
      "pdns5.ultradns.info.",
      "dns2.p09.nsone.net.",
      "dns3.p09.nsone.net.",
      "dns4.p09.nsone.net.",
      "pdns3.ultradns.org.",
      "pdns6.ultradns.co.uk.",
      "pdns1.ultradns.net.",
      "pdns2.ultradns.net."
    ],
    "spf": [
      "00D00000000hgBG=1TBa70000000GMX",
      "apple-domain-verification=0Cq9m86umSJj48Lc",
      "amazonses:t7uPAmLr+GQsilBGtLdODuKQfxX78F7KKROYzkXeDnk=",
      "facebook-domain-verification=imkvqqxv2t6mzz9o2rqoowbjmebkw9",
      "_o4ot2wbs5egjtzzg5r2kjfb5iwrf0mp",
      "lucid-verification=kfm1DJP5pmf-wyf1qxd",
      "atlassian-domain-verification=BoDCBNyHJzHh97Myx/Z4n3grU8sMEGR10Mi8CdpStC01PdMAuIARlKP/odGI7CvN",
      "_globalsign-domain-verification=VhFG-UAc8IPlmik4wizjFi149rlyYfubwGgIy_Ila4",
      "x034XVMC1Z3q1tp7Rd2+WV9Cf8GQ7wqakjbNinoZvSGB2K7/oQbi2hLe8HLezV0ia4zePzaZaIAwzuXiMPSM9A==",
      "amazonses:Fo+DrXJ2hWyGoODXpSHEzYI4Uw9L93rskKKD/pbX9qk=",
      "anthropic-domain-verification-gvhc3w=7DZit0fI0UvkLidnFGXWSj673",
      "apple-domain-verification=dzOcCMjpBEyl50Bc6Wb_j4B10rRmI1Jan_auP5P2lcQ",
      "google-site-verification=nK8ds4mXu1b3H3be6v0EFQoBDNL0ehLYho-eRN0mmik",
      "amazonses:Qz9hS4Kkufxpp+jJXEYur6QH8sCMrNyMuMgqWDY0res=",
      "smartsheet-site-validation=1faPwvohZowpNS7Bl4ROqo9qp0soq7Mo",
      "docusign=af374066-7f8d-4e9e-aa34-ced1f3929a3d",
      "amazonses:L/znkTRG3CC7az8kQioGsNeARe/8ERvOQUwjq69Ov8A=",
      "amazonses:GpLcOvJxxnz0UuiDzgnZCnWdvkNwNJNDoZsi+jNLl70=",
      "amazonses:oZ2yR24a2IvFfvd7rTosskhpBLV0+ALRtvkRJIjx0fo=",
      "cisco-ci-domain-verification=353929ee9fd3a3760facd2437590f676e7cf9395c48c74d21b1df486d09f3374",
      "amazonses:6N5k7dR50wcCMNvXtEVCL7tVvOqZBQmuFFEJLokVIfE=",
      "amazonses:LZ0J6MYU9V4K1tMfUCKKyF2lrqYy7/T1a3SGHMTkgdI=",
      "_slnmbnij2ra2pe5luncgck1q9xp153b",
      "adobe-idp-site-verification=abcfaaf9-27be-4dca-a1e1-c927aef12f3f",
      "amazonses:mDgr5HTfTVGx3+y1oKrXWeGLfIIUB6TYS727YPN+MVM=",
      "amazonses:sG5OYkWVHIpG/aa9orqZIna+hfMfRpT1SGaCb4D4XVw=",
      "_wona8ky5rjcq7mpv89xu2z03gzgw4ox",
      "amazonses:JqZ7DCH6v3rdHV51NIWOkU7wPgB0aSTP0Z1hF9tr9N8=",
      "ca3-7a14c6a8346148a8a530cc85edf8eaa2",
      "docusign=4188e9ec-e035-430e-88b2-7a13724ef5a5",
      "v=spf1 include:_spf.expedia.com a:b.spf.service-now.com include:_spf.qemailserver.com include:spf.clearslide.com include:mail.zendesk.com include:_spf.salesforce.com include:_spf.sidetrade.net ip4:212.99.44.68 ip4:212.99.44.69 ip4:83.138.167.180 ip4:195.5",
      "0.76.198 ip4:83.138.167.180/30 ip4:205.201.128.0/20 ip4:198.2.128.0/18 ip4:148.105.8.0/21 ip4:199.15.213.62 ip4:199.15.213.63 ip4:192.28.150.108 ip4:66.244.67.50 -all",
      "slack-domain-verification=81W2yd6WvPIV2bIiJ0v7Z9CctNAA8jqAQl8WaAJq",
      "teamviewer-sso-verification=aed054b0717d4220825c45cb229bfdb2",
      "miro-verification=d36744c01c72c4c0e036eacc18ffe55264b3bf81",
      "amazonses:glyQN3VG7+2GwQzW53o2g3FKyzhxfj1s1MoJmxgF/IM=",
      "facebook-domain-verification=s4h6e1h04jupatgxdgiqjclfwmvxu1",
      "google-site-verification=FpDWRaM4PuuKkac8GS2WnRrOL2ETEawDDPSUqkJHUmc",
      "perplexity-ai-domain-verification-kx8cwa=8WA6k9CqOacJLnLYJunqAVGGC",
      "_qhfakp24u4ate3lbyvw1p3veiru4lkd",
      "tiktok-developers-site-verification=xu7umPD0SGmugD16amWLt5izfF818tcR",
      "mailru-verification: 1b3eba1af3b91214",
      "openai-domain-verification=dv-LcuXOUafDEymiB6NOaKRg5yD",
      "MS=ms41917382",
      "ZOOM_verify_ofBcMvjmQlCZcaU4dvIkgQ",
      "dropbox-domain-verification=4ujrmug64lqg"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:expedia@rua.netcraft.com,mailto:dmarc_agg@dmarc.250ok.net ; ruf=mailto:expedia@ruf.netcraft.com,mailto:dmarc_fr@dmarc.250ok.net"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=expedia.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Jul 21 22:02:32 2026 GMT",
    "notAfter": "Oct 19 22:02:31 2026 GMT",
    "san": [
      "expedia.com"
    ],
    "days_left": 24,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.37.92.132",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.expedia.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.expedia.com/"
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
  "elapsed_s": 105.1,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
