# Security Audit Report — constantcontact.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://constantcontact.com/ |
| Bug bounty program | Constant Contact |
| Listed scope domain | constantcontact.com |
| Test date | 2026-09-25 09:07 UTC |
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
- **Detail:** Detected: Server: Apache
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
- **Detail:** Header reveals: Apache
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
  "domain": "constantcontact.com",
  "dns": {
    "a": [
      "208.75.122.14"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "edgemail1.constantcontact.com (pref 10)",
      "edgemail2.constantcontact.com (pref 20)"
    ],
    "ns": [
      "dns2.p01.nsone.net.",
      "dns1.p01.nsone.net.",
      "dns4.p01.nsone.net.",
      "dns3.p01.nsone.net."
    ],
    "spf": [
      "jamf-site-verification=aFdwoWd1sPeHAeoixINgyw",
      "globalsign-domain-verification=1FF969BDF7F6D9B06243EFA8042CBDE7",
      "globalsign-domain-verification=A899C94328AC5076D4198E6055E9C6E1",
      "ps-cd-verification=3e13eeb0-a25b-41af-a9d1-d5c8cca8082a",
      "google-site-verification=ALoYvB9LP05aK7ddKNWCSrNKI4QPPh647yXxmNq1rJ4",
      "Cb20W914dVUL9V8ziCkX1Qo",
      "globalsign-domain-verification=F1462C7038793BEEB6A1FCE7B31E06B7",
      "facebook-domain-verification=9wo9l62thl595soh1wjzolqfv3ao8c",
      "v=spf1 ip4:208.75.120.0/22 ip4:205.207.104.0/22 include:_ext.constantcontact.com include:_spf.salesforce.com include:_spf.google.com ~all",
      "reachdesk-verification=1CmlRrcJcF7N7kW8ionhhGt21vydYDeiaGjRKoFAJHCsTyxLVFHOcdUBxBeUrt3H",
      "meltwater_sso_20260521_triton-36710",
      "google-site-verification=9SlseBmCRNaS8PoCIcXUBYR18HWP6RBX9HyD3R5R5Ls",
      "globalsign-domain-verification=5C905CAD6161760D48FA250433C2EEF9",
      "SFMC-nnhzrK01oLNsym2xcDKcUEXUlbm8OIrlrUxoOGdS",
      "cisco-ci-domain-verification=2bd65a16476143d0aebade20fdf9ca88de20694b28dbd9a7630bd6a72c690a63",
      "globalsign-domain-verification=607B2BE93D2B60F139751C389A14C13B",
      "globalsign-domain-verification=D5A7AFA31C2BFA6174B52F0F9E90C9DF",
      "validity-domain-monitoring=lWgicWp5GPvLfdEoFXdAYpMXV",
      "google-site-verification=lMXxJuCIadZI6yIKv7z5_Va70POuM19qU81NU0tmaxI",
      "globalsign-domain-verification=C385682A22F86586CCE2465D9544AA1C",
      "MS=ms18093078",
      "v0IqpOXySDIxu292XtWFBWVQ2T3C/MLnpiy5EKsfKWg=.",
      "anthropic-domain-verification-y2453z=RP4EoX2XlEAObiHw4Qyfxyif2",
      "docusign=d814c280-26f9-41c7-aa92-a03b59e6fd58",
      "google-site-verification=GEYwmfZ7RuvBcI7BT6xQnrNfn1z7gWUKLfVIalnwqeA",
      "google-site-verification=S0PJ1RSXkRxVn-okVzPY9Lzeghej1eIywqeTx0o2MKE",
      "TAILSCALE-WN5I3ZooiwxJsVakFdjs",
      "duo_sso_verification=7HPXqXi0wOuCX7DdMLeu09LySVwMqymRiBWo3e5f1J9JumDaZTfzYPxfcpnbQCRi",
      "stripe-verification=685340051470B5606798FED265AD82838FDC4D525047AEBAC6F8577B731D91CA",
      "atlassian-domain-verification=fMjaVWKHpJhM3aAlDYkNe5/yuAOUIOva2QexA9BN3WIHOkZmfqX9AWdaOicLtJYr",
      "google-site-verification=5lHEZKPh-_wYKf6iPhatHRpXj2l0R9NmPQ9wSWIAQag",
      "kF4qrcASQQx6dXlhtT5OqM1QkLhxmOFd9TIEk0+L+Hg=.",
      "globalsign-domain-verification=83DF7D9B4CADBA9AB6D6ED1792F009A4",
      "ZOOM_verify_lz7Vk7Mf3ZEzuB6jwtCEVv",
      "logmein-verification-code=491874e6-5c3b-4b37-b19e-f523d7d74473",
      "globalsign-domain-verification=1FF9A93F847B1EB612F7EB378BFA8F2F",
      "globalsign-domain-verification=6FFE99D6D65D30A44C49A374C5143D87",
      "google-site-verification=Gp7Hv6yLosjKQ_t7gHJROnXoAYK7wlz1XLOBHt_J7HE",
      "spf2.0/pra ip4:208.75.120.0/22 ip4:205.207.104.0/22 include:_ext.constantcontact.com include:_spf.salesforce.com include:_spf.google.com ~all",
      "google-site-verification=RMx0cdA4nEA6nAg48o0lsv4eb29EbVafa7weQBnSNJQ",
      "openai-domain-verification=dv-tjo2gRJDV0e90MlGZWURanbs",
      "globalsign-domain-verification=FA2D0568288440FE444CE3BEE2B3FD88",
      "pendo-domain-verification=n9rM3WLge63EWPA3kOPW1OUEcXg",
      "google-site-verification=JtNhbwEnbIVid2N5wO0kF9kJ5jfx_ttYqfleBTqKZJY",
      "MS=91FCD146A8340927C3F9723C8F3DC44A5AE57414",
      "MS=ms76971383",
      "cursor-domain-verification-fad4vy=0NZxtFJAF9pFISdFqx3nMzNyk",
      "canva-site-verification=ZyZ5z6fQIoIHCDU_U8K6YQ",
      "validate.onetrust-domain-verification=8c431f2bfba744d99f5df0ee4ef55df1",
      "tgXS6TJ3fVTnME8cpaIfgd9fe2rkAsn8kgSVRi/Af/c="
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:tk0syg54@ag.dmarcian.com,mailto:dmarc_agg@vali.email; ruf=mailto:tk0syg54@fr.dmarcian.com; rf=afrf;"
    ],
    "dnssec_authenticated": false
  },
  "elapsed_s": 15.7,
  "subdomains": {
    "status": "crt.sh 502 (certspotter 429)"
  },
  "rechecked": "2026-09-25 10:43 UTC",
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Apache"
  ],
  "cookies": [
    {}
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.constantcontact.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.constantcontact.com/"
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
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 301,
    "/server-status": 404,
    "/api/": 301
  }
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
