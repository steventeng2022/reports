# Security Audit Report — docker.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://docker.com/ |
| Bug bounty program | Docker |
| Listed scope domain | docker.com |
| Test date | 2026-09-26 17:43 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 4, Info: 12)

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
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Pantheon
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
- **Detail:** Header reveals: Pantheon
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

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=CFmV0geNs1hCxK0mBEpjWaDoNwBIiDxIRjTvt3YGRDM; jamf-site-verification=jqNgc5MzMp4UnSANweyyEQ; opine-verification=14d8ea53-d8ae-406f-93b0-76dc879d9b46
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of docker.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 24 disallow path(s), e.g. /wp-admin/, /pricing/contact-sales/bss-cc-thankyou/, /pricing/contact-sales/bss-thankyou/, /company/contact-thank-you/, /thank-you-subscribing-docker-weekly/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "docker.com",
  "dns": {
    "a": [
      "23.185.0.4"
    ],
    "aaaa": [
      "2620:12a:8001::4",
      "2620:12a:8000::4"
    ],
    "cname": null,
    "mx": [
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-1289.awsdns-33.org.",
      "ns-1981.awsdns-55.co.uk.",
      "ns-568.awsdns-07.net.",
      "ns-207.awsdns-25.com."
    ],
    "spf": [
      "google-site-verification=CFmV0geNs1hCxK0mBEpjWaDoNwBIiDxIRjTvt3YGRDM",
      "jamf-site-verification=jqNgc5MzMp4UnSANweyyEQ",
      "opine-verification=14d8ea53-d8ae-406f-93b0-76dc879d9b46",
      "cursor-domain-verification-pkwbtp=KD6kIrkeudCadzeviiVJgEWnd",
      "adobe-idp-site-verification=a8d1a71d0cba44c2521bcb451d9dc708ee20d93c7b5b04791f699d128bbe6ec2",
      "detectify-verification=87a64c3bf3301354588d90672bd1b74e",
      "zapier-domain-verification-challenge=c3e7ddaf-20bf-40ca-9374-1a917b16be06",
      "google-site-verification=rCKOZlVmB_xuu9DiT-urSmmXAEUGn5RI8PxdyCW5LJg",
      "docusign=aeb25cd4-f743-4efc-b6fb-b8bc5dd1d0e8",
      "google-site-verification=Nyiwo5q4kkaD5V-sEiXsW74HXyVRtKVyxYFfZuFLG7M",
      "MS=ms98031138",
      "stripe-verification=804359af3a919b4a46343227e384abdf33e10ad5bb81ea9f1d17ed4e74486ab4",
      "onetrust-domain-verification=fb12882ae6344670a7b91077bd57c0f1",
      "MS=ms42223923",
      "d0vcwvtyam",
      "google-site-verification=GjEZ_3KyjpDbmRzGdMUtqMeuXdh7HCSc8uRsPGYL-I0",
      "google-site-verification=4PyKLfy_lowkc_qcu-byUkmF1kxAUT7tfho7ZiP353s",
      "openai-domain-verification=dv-tj9VEsgExQvdNl9SCOa2Awju",
      "google-site-verification=i6hYWAXRYCtHNnyiQAYXiy_4StkAMJQiNCfH-3olY-I",
      "google-site-verification=VbuWA5NflxQMko2x9BJFIPVYrbuxHQll4UP4gZ4Fm08",
      "google-site-verification=5e33xBJIwW1XU49IqmIYtN7yi2Iq0GNnWwN4ujn4G_M",
      "apple-domain-verification=S580UenDqcwy2I1X",
      "sinch-domain-verification=d8a66194-44cf-49c3-96ab-74325ad6e7be",
      "atlassian-domain-verification=I1f5bgOm9sPUEcK/2JTD6weNlWt+Wwsyo5dwvJe1fGjf9V+x3kyqxZRrl9z7ILEK",
      "airtable-verification=7f122efe7db6b16848108e469042c39c",
      "sonatype-domain-verification=OSSRH-62474",
      "docker-verification=4b72827b-32c1-4fe6-a843-2256c0df8a31",
      "v=spf1 include:_spf.google.com include:spf.tipalti.com include:_spf.salesforce.com include:mktomail.com include:mail.zendesk.com -all",
      "anthropic-domain-verification-p1ks1q=BmUzJzzDzqNXVWLXmZVoEvTr3",
      "miro-verification=116f0987438eb5a48c070e080a68e7d7b3087e5f",
      "astro-domain-verification=cljrj1fgz00hm01lvtaq65gnn"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=100; rua=mailto:q1xwnepx@ag.dmarcian.com; ruf=mailto:q1xwnepx@fr.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=docker.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Jul 30 10:32:24 2026 GMT",
    "notAfter": "Oct 28 10:32:23 2026 GMT",
    "san": [
      "docker.com",
      "www.docker.com"
    ],
    "days_left": 31,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.185.0.4",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Pantheon"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.docker.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.docker.com/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=CFmV0geNs1hCxK0mBEpjWaDoNwBIiDxIRjTvt3YGRDM",
    "jamf-site-verification=jqNgc5MzMp4UnSANweyyEQ",
    "opine-verification=14d8ea53-d8ae-406f-93b0-76dc879d9b46",
    "cursor-domain-verification-pkwbtp=KD6kIrkeudCadzeviiVJgEWnd",
    "adobe-idp-site-verification=a8d1a71d0cba44c2521bcb451d9dc708ee20d93c7b5b04791f69"
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
  "http2": {
    "robots_disallow": [
      "/wp-admin/",
      "/pricing/contact-sales/bss-cc-thankyou/",
      "/pricing/contact-sales/bss-thankyou/",
      "/company/contact-thank-you/",
      "/thank-you-subscribing-docker-weekly/",
      "/pricing/contact-sales2/",
      "/cdn-cgi/",
      "/static/",
      "/c/",
      "/p/",
      "/products/telepresence-for-docker/thank-you/",
      "/style-guide/",
      "/search/",
      "/ja-jp/wp-admin/",
      "/ja-jp/pricing/contact-sales/bss-cc-thankyou/"
    ]
  },
  "elapsed_s": 22.4,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
