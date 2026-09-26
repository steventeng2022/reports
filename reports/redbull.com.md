# Security Audit Report — redbull.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://redbull.com/ |
| Bug bounty program | Redbull |
| Listed scope domain | redbull.com |
| Test date | 2026-09-26 22:14 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

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
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 17 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |

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
- **Detail:** Apex TXT records with verification/token content: notion-domain-verification=hN2mHaKh119t9oIeUxOZ3tMcWasvrx4wAOUBR7gEgfY; yandex-verification: aad18f620b64b27c; google-site-verification=FT9NwKVuURPQaWb5Fq7oVSA7l5r_OebpkZ8ySQLlOIY
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.208.12.186 carries PTR a23-208-12-186.deploy.static.akamaitechnologies.com. for redbull.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for redbull.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 17. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The redbull.com certificate lists an AIA OCSP responder (http://ocsp.sectigo.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

## Evidence (raw response observations)

```json
{
  "domain": "redbull.com",
  "dns": {
    "a": [
      "23.208.12.186",
      "23.208.12.170"
    ],
    "aaaa": [
      "2600:1417:8400:31::17ce:cb47",
      "2600:1417:8400:31::17ce:cb46"
    ],
    "cname": null,
    "mx": [
      "redbull-com.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "pdns91.ultradns.biz.",
      "pdns91.ultradns.com.",
      "ns15.ultradns2.com.",
      "pdns91.ultradns.net.",
      "ns15.ultradns2.org.",
      "pdns91.ultradns.org."
    ],
    "caa": [],
    "spf": [
      "notion-domain-verification=hN2mHaKh119t9oIeUxOZ3tMcWasvrx4wAOUBR7gEgfY",
      "yandex-verification: aad18f620b64b27c",
      "google-site-verification=FT9NwKVuURPQaWb5Fq7oVSA7l5r_OebpkZ8ySQLlOIY",
      "_ryr62gyfim9w9j6y96gb4hido52o87c",
      "globalsign-domain-verification=hL1YyaIXzf8_UoxDhIMWaHVWUANe7eU7dWvXus7lwI",
      "google-site-verification=cAAOttK7KB-rKBmOD7p1Imx6EcdvKD-DLIvoDclN8YA",
      "anthropic-domain-verification-5wg0q8=Drbo9cZiHvN1d2LNdDTEpoRku",
      "cm.com-domain-verification=648a8834-79b1-4072-9fcc-01a85c8f8c22",
      "spycloud-domain-verification=7b0d7b29-0783-43a8-ae02-2618020eb9d0",
      "figma-domain-verification=7a82465e7631432ddae7da5c5874d4fd7bdefc2c5eabd1baca75d219dc388f58-1725268196",
      "MS=ms97463818",
      "firebase=redbull-photobooth-fansite",
      "uber-domain-verification=345f84e7-8f29-4772-8a95-437d5755fd97",
      "google-site-verification=zdiNmEZSzIJoZazEYew3bFFSXqudF7ODAHqljjf9hjg",
      "yandex-verification: a51dcd774998eab8",
      "zapier-domain-verification-challenge=112b278f-86f3-41a1-896b-d581fb935e34",
      "docusign=679758f7-e6bc-41ab-8dbf-417624c378a4",
      "vector-saml-92020417",
      "atlassian-domain-verification=SE0bg/sLbNj/sxFjb5WzNowyB2EHWNhe/j4JbSYgLllAii8XsA6kVaTiLiQS7Kr7",
      "jamf-site-verification=_T1tJfEpBa5y1V4i5ongPw",
      "monday-com-verification=qVsHJCKBqguw6NvEWYm9FSUma88aPXmBM__iEh_LcdU",
      "fastly-domain-delegation-l6ByU9UvR9NX06q-20251121",
      "Ws0bd7f6/5qF5IIq/WdhyrANdPcnsIiWWLi0IaWO5cKb/CFj6cBCGx2siy/4UFRc0e2FMOB0+FUmWeos/leuYg==",
      "google-site-verification=dyaNOA-sacV_MOg8KnODyK8ihwNa368Vz0Hq2_5MpcY",
      "workplace-domain-verification=G6JbgsDS3rGKm9xjdExKVXP3uazq8P",
      "google-site-verification=x_6pn1VmeoS7F3VrlNiZye1yb0RXleXiW2psI9flRBY",
      "adobe-idp-site-verification=f7adf3e3b2e02fdafc5d0da23da483f36bbf68c3d554a3bb94db66190116545f",
      "atlassian-sending-domain-verification=3531ce11-63aa-453d-a854-4ab6aad86fcf",
      "atlassian-domain-verification=6JjO48MB9UypL10pMDk0vdlEGRGtdMztJavx3KTtMJerMz/adr2Ks0qr+55+LpoQ",
      "virtru-site-verify=obp3KuFTAvVACEbB28a2PkjY9bvEQhygmi7gd3d6",
      "ciscocidomainverification=484a6f952eb1e97a5d6a12260122d88095307403a3c873f524b55a8a09e0311c",
      "v=spf1 include:spf.protection.outlook.com include:_spf.redbull.com include:spf.virtrugateway.com -all",
      "f7fbf1eb4bb2bd20afa0e38447eff8dc3d66a2c953e59e527a",
      "apple-domain-verification=odkhNiY1AwjKsHAl",
      "amazonses:pkdkj6bcdiVxa2xtsoMA70kc1PyYjNtUzGcLZGHWXQk=",
      "facebook-domain-verification=uhk1v8zuggj2ug6q0e9f1hczlzz1jr",
      "webexdomainverification.C5UR=281b4db8-b67c-4111-9ece-8958b41cd08f",
      "mongodb-site-verification=s4RGRapyJSjdREFYPXqvzHmYt60COynM",
      "docusign=b3640d57-0668-4c84-a5cb-4e199fd00d38",
      "teamviewer-sso-verification=3d50f93de59b453aa294796293a115d0",
      "google-site-verification=wjAcjCp-XN8rKlZWz47ImMiC6gYoaVe5So6Yl7YhHk0",
      "TGTRxhxdWsMPjij6aytGGneMBuVXCl/yZnJjLxOrka4s+20mUfT10boKi26Gucz3BPhpnzjLSLk+ktKl9sGJxw==",
      "QuoVadis=d56f7361-359a-4f04-b858-2e34d9d9b117",
      "ZOOM_verify_m27rLBztRkeFHLDKbAtzuA",
      "neat-pulse-domain-verification-W8XZ4xN=35c9459f-5f1d-48dc-a8dc-fcd480a2e5f1",
      "_uy14g9zokx3stw6c10e7kacxl2krs0h",
      "canva-site-verification=CpUH3-GXSXlisKiHbnI6kw"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:zsrbf6su@ag.eu.dmarcadvisor.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=AT, stateOrProvinceName=Salzburg, organizationName=Red Bull GmbH, commonName=redbull.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA OV E36",
    "notBefore": "Aug 13 00:00:00 2026 GMT",
    "notAfter": "Feb 27 23:59:59 2027 GMT",
    "san": [
      "redbull.com",
      "www.redbull.com"
    ],
    "days_left": 154,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.208.12.186",
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
      "origin": "https://sub.redbull.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.redbull.com/"
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
    "notion-domain-verification=hN2mHaKh119t9oIeUxOZ3tMcWasvrx4wAOUBR7gEgfY",
    "yandex-verification: aad18f620b64b27c",
    "google-site-verification=FT9NwKVuURPQaWb5Fq7oVSA7l5r_OebpkZ8ySQLlOIY",
    "globalsign-domain-verification=hL1YyaIXzf8_UoxDhIMWaHVWUANe7eU7dWvXus7lwI",
    "google-site-verification=cAAOttK7KB-rKBmOD7p1Imx6EcdvKD-DLIvoDclN8YA"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": "http://ocsp.sectigo.com",
      "not_before": "20260813000000",
      "not_after": "20270227235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a23-208-12-186.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.redbull.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 11.7,
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
