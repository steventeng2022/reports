# Security Audit Report — lenovo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://lenovo.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | lenovo.com |
| Test date | 2026-09-25 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 5, Info: 7)

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
| 11 | low | RED1 | HTTP redirect points to another host over plain HTTP | CWE-319 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
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
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [LOW] HTTP redirect points to another host over plain HTTP (`RED1`)

- **CWE:** CWE-319
- **Detail:** Location: http://www.lenovo.com/
- **Context:** https response, /
- **Recommendation:** Redirect to the same host over HTTPS.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "lenovo.com",
  "dns": {
    "a": [
      "104.115.211.7"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "lenovo-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "a24-65.akam.net.",
      "a3-67.akam.net.",
      "a28-66.akam.net.",
      "a1-79.akam.net.",
      "a8-64.akam.net.",
      "a11-64.akam.net."
    ],
    "spf": [
      "google-gws-recovery-domain-verification=53030486",
      "google-site-verification=IGQvpRBrmSETWSziSpzxK4YIjUVeTyNb5mTytcatDD8",
      "v=spf1 include:spf.lenovo.com include:vendorspf.lenovo.com ~all",
      "google-site-verification=hxNSoF46anzjUtyFgpRVpzshTkYClFBJ7OAT3Dz6440",
      "63posrsg6o3q95dtuc80da228n",
      "airtable-verification=1d5415310fbcf1fdc72c0b175208089a",
      "duo_sso_verification=2eFmztpfk73LXpFC92aOkVdh4qWYBJ169vmf2WqC2omGJBXPVugwvp3gTFjX8cr2",
      "duo_sso_verification=sKtyF9pQMvjVPX6vq4nzV00r7qKNkEVAkkb0Tlx1om1ZqroOG1eZEexVxJr0kfAY",
      "google-site-verification=vyPsFusgDLeWzvnapRyBbiva5dXJ1JIJjcNbGuO52-k",
      "4b60110d90a0ba16827618f3165cf720c5458664c9392ea157363087784e0292",
      "MS=ms38130575",
      "google-site-verification=VxW_e6r_Ka7A518qfX2MmIMHGnkpGbnACsjSxKFCBw0",
      "_0nv5veu70xwpobopaobpzyaqo6i9iv8",
      "openai-domain-verification=dv-w6UANk0E74dbpJI3mTMHPfxP",
      "Visit www.lenovo.com/think for information about Lenovo products and services",
      "_globalsign-domain-verification=4qaYYFkDr3zY8xFnX817RHQdbwKtr7S6GWVF9HLJ3P",
      "fastly-domain-delegation-Gg2T0SlTwT-2021-03-09",
      "google-site-verification=sHIlSlj0U6UnCDkfHp1AolWgVEvDjWvc0TR4KaysD2c",
      "a82c74b37aa84e7c8580f0e32f4d795d",
      "google-site-verification=nGgukcp60rC-gFxMOJw1NHH0B4VnSchRrlfWV-He_tE",
      "x1n4n7dfpt5hlqlv6vpbtg2czj5bk2y8",
      "qh7hdmqm4lzs85p704d6wsybgrpsly0j",
      "Dynatrace-site-verification=9bffa29b-0dbd-4e8f-8c8c-b28fca3b1bdf__49s5b44hnes32j605089h3f60a",
      "pendo-domain-verification=KCqOPkCxJXwRvhV7udrsxm7aBQg",
      "iEf8OeY/ebUNJkh8rH9jcDmdS7Uq9B5wNePdkhhqLVHgHP4eekupSYlmdsz+e3Y59/XTCbHY40h1BtI5cpfDJw==",
      "ece42d7743c84d6889abda7011fe6f53",
      "atlassian-domain-verification=lBI3riiS/hlfifAaegKM2zDr7vf//HR7mVq7kfQbtMrynu8eQKK3NyDc7EVwWPRs",
      "_dnsauth=4hlzyrmrk0hdkk4c96qw745ll5h58x35",
      "adobe-idp-site-verification=5540c96206f5fe2df921a6c596ea9fb3d7e418d3eddb598c29935cc03163805b",
      "qctqpsq058s3t12m0rjf2jxw8jnvn0zr",
      "figma-domain-verification=77471062f3395d7cb96639684e519d0b3d276830c64ca7e17ea13b8f28203680-1772698461",
      "google-site-verification=KT4YATm6NeQqaD0WLCJtFOjb0gYXhbzUekUM9Rm-fb8",
      "facebook-domain-verification=1r2am7c2bhzrxpqyt0mda0djoquqsi",
      "_globalsign-domain-verification=feXxUwi7bGccktj7bI7l7OYmFCm_x8ogmN1-U4Hu-T",
      "smartsheet-site-validation=rRKFFSIrRIhcJ7s3nfiTgTC_jH46Dlu_",
      "cursor-domain-verification-k5ed5k=vc6Qb8LpyNVHcyT7pkGQklhoh",
      "google-site-verification=247PPmmalrNARHoE2rmOJ3YQygtMquQwLpM_LzVXsFg",
      "figma-domain-verification=8b6b33942e392f3a6b635697b081e78986a6854d82587c11ae4b1b3bd257b6f1-1784306874",
      "google-site-verification=HESboqU3DntBTT9PbwXRvCBnD3atK7HWgIcv3TJcllw",
      "google-site-verification=1dLAd9aAmT5IZx0wSSkxrD-Fk3izPYLC3Hw_nCQ56sw",
      "atlassian-domain-verification=Vx1wgyd3FWPEj1cw8sYFv4k6przB3O0EzfmiVawbgV4nMmAqY0fcCo6BeaOrg24G"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua@lenovo.com,mailto:bzo4atck@ag.ap.dmarcian.com; ruf=mailto:dmarc_ruf@lenovo.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=MY, localityName=Petaling Jaya, organizationName=Lenovo Technology Sdn. Bhd., commonName=*.lenovo.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jul 17 00:00:00 2026 GMT",
    "notAfter": "Jan 31 23:59:59 2027 GMT",
    "san": [
      "*.lenovo.com",
      "lenovo.com"
    ],
    "days_left": 128,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.115.211.7",
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
      "origin": "https://sub.lenovo.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "http://www.lenovo.com/"
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
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 25.8,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
