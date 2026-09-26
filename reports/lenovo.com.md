# Security Audit Report — lenovo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://lenovo.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | lenovo.com |
| Test date | 2026-09-26 22:09 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 5, Info: 13)

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
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |

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

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=Vx1wgyd3FWPEj1cw8sYFv4k6przB3O0EzfmiVawbgV4nMmAqY0; airtable-verification=1d5415310fbcf1fdc72c0b175208089a; google-site-verification=vyPsFusgDLeWzvnapRyBbiva5dXJ1JIJjcNbGuO52-k
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.digicert.com -> http-200
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.49.123.153 carries PTR a23-49-123-153.deploy.static.akamaitechnologies.com. for lenovo.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for lenovo.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

## Evidence (raw response observations)

```json
{
  "domain": "lenovo.com",
  "dns": {
    "a": [
      "23.49.123.153"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "lenovo-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "a24-65.akam.net.",
      "a28-66.akam.net.",
      "a8-64.akam.net.",
      "a3-67.akam.net.",
      "a11-64.akam.net.",
      "a1-79.akam.net."
    ],
    "caa": [],
    "spf": [
      "smartsheet-site-validation=rRKFFSIrRIhcJ7s3nfiTgTC_jH46Dlu_",
      "iEf8OeY/ebUNJkh8rH9jcDmdS7Uq9B5wNePdkhhqLVHgHP4eekupSYlmdsz+e3Y59/XTCbHY40h1BtI5cpfDJw==",
      "atlassian-domain-verification=Vx1wgyd3FWPEj1cw8sYFv4k6przB3O0EzfmiVawbgV4nMmAqY0fcCo6BeaOrg24G",
      "x1n4n7dfpt5hlqlv6vpbtg2czj5bk2y8",
      "airtable-verification=1d5415310fbcf1fdc72c0b175208089a",
      "google-site-verification=vyPsFusgDLeWzvnapRyBbiva5dXJ1JIJjcNbGuO52-k",
      "figma-domain-verification=77471062f3395d7cb96639684e519d0b3d276830c64ca7e17ea13b8f28203680-1772698461",
      "qh7hdmqm4lzs85p704d6wsybgrpsly0j",
      "_dnsauth=4hlzyrmrk0hdkk4c96qw745ll5h58x35",
      "google-site-verification=sHIlSlj0U6UnCDkfHp1AolWgVEvDjWvc0TR4KaysD2c",
      "google-site-verification=HESboqU3DntBTT9PbwXRvCBnD3atK7HWgIcv3TJcllw",
      "63posrsg6o3q95dtuc80da228n",
      "google-gws-recovery-domain-verification=53030486",
      "atlassian-domain-verification=lBI3riiS/hlfifAaegKM2zDr7vf//HR7mVq7kfQbtMrynu8eQKK3NyDc7EVwWPRs",
      "fastly-domain-delegation-Gg2T0SlTwT-2021-03-09",
      "cursor-domain-verification-k5ed5k=vc6Qb8LpyNVHcyT7pkGQklhoh",
      "google-site-verification=hxNSoF46anzjUtyFgpRVpzshTkYClFBJ7OAT3Dz6440",
      "MS=ms38130575",
      "google-site-verification=VxW_e6r_Ka7A518qfX2MmIMHGnkpGbnACsjSxKFCBw0",
      "figma-domain-verification=8b6b33942e392f3a6b635697b081e78986a6854d82587c11ae4b1b3bd257b6f1-1784306874",
      "duo_sso_verification=2eFmztpfk73LXpFC92aOkVdh4qWYBJ169vmf2WqC2omGJBXPVugwvp3gTFjX8cr2",
      "_0nv5veu70xwpobopaobpzyaqo6i9iv8",
      "adobe-idp-site-verification=5540c96206f5fe2df921a6c596ea9fb3d7e418d3eddb598c29935cc03163805b",
      "google-site-verification=247PPmmalrNARHoE2rmOJ3YQygtMquQwLpM_LzVXsFg",
      "google-site-verification=KT4YATm6NeQqaD0WLCJtFOjb0gYXhbzUekUM9Rm-fb8",
      "openai-domain-verification=dv-w6UANk0E74dbpJI3mTMHPfxP",
      "facebook-domain-verification=1r2am7c2bhzrxpqyt0mda0djoquqsi",
      "ece42d7743c84d6889abda7011fe6f53",
      "_globalsign-domain-verification=feXxUwi7bGccktj7bI7l7OYmFCm_x8ogmN1-U4Hu-T",
      "duo_sso_verification=sKtyF9pQMvjVPX6vq4nzV00r7qKNkEVAkkb0Tlx1om1ZqroOG1eZEexVxJr0kfAY",
      "google-site-verification=IGQvpRBrmSETWSziSpzxK4YIjUVeTyNb5mTytcatDD8",
      "v=spf1 include:spf.lenovo.com include:vendorspf.lenovo.com ~all",
      "Dynatrace-site-verification=9bffa29b-0dbd-4e8f-8c8c-b28fca3b1bdf__49s5b44hnes32j605089h3f60a",
      "a82c74b37aa84e7c8580f0e32f4d795d",
      "google-site-verification=nGgukcp60rC-gFxMOJw1NHH0B4VnSchRrlfWV-He_tE",
      "pendo-domain-verification=KCqOPkCxJXwRvhV7udrsxm7aBQg",
      "google-site-verification=1dLAd9aAmT5IZx0wSSkxrD-Fk3izPYLC3Hw_nCQ56sw",
      "4b60110d90a0ba16827618f3165cf720c5458664c9392ea157363087784e0292",
      "qctqpsq058s3t12m0rjf2jxw8jnvn0zr",
      "_globalsign-domain-verification=4qaYYFkDr3zY8xFnX817RHQdbwKtr7S6GWVF9HLJ3P",
      "Visit www.lenovo.com/think for information about Lenovo products and services"
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
    "days_left": 127,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.49.123.153",
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "atlassian-domain-verification=Vx1wgyd3FWPEj1cw8sYFv4k6przB3O0EzfmiVawbgV4nMmAqY0",
    "airtable-verification=1d5415310fbcf1fdc72c0b175208089a",
    "google-site-verification=vyPsFusgDLeWzvnapRyBbiva5dXJ1JIJjcNbGuO52-k",
    "figma-domain-verification=77471062f3395d7cb96639684e519d0b3d276830c64ca7e17ea13b",
    "google-site-verification=sHIlSlj0U6UnCDkfHp1AolWgVEvDjWvc0TR4KaysD2c"
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
      "aia_ocsp": "http://ocsp.digicert.com",
      "not_before": "20260717000000",
      "not_after": "20270131235959"
    },
    "ocsp": "http-200"
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a23-49-123-153.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.lenovo.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 7.7,
  "rechecked": "2026-09-26 21:56 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- Findings are reported against the public program scope; submission through the program tracker is pending.
