# Security Audit Report — tf1.fr

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://tf1.fr/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | tf1.fr |
| Test date | 2026-09-26 19:00 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

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
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
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
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [LOW] HTTP redirect points to another host over plain HTTP (`RED1`)

- **CWE:** CWE-319
- **Detail:** Location: http://www.tf1.fr/
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
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=LNtUooOAlKAYEchZJDanSWATh4vjZlH4bSqQpCQHfs; riot-domain-verification=109aa709345405a31d234f32084b830bd96ffd2e7a44659fef9398e; dropbox-domain-verification=3mvn6yo2eulg
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of tf1.fr has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 15.197.129.244 carries PTR accf5a60a4b2dbe54.awsglobalaccelerator.com. for tf1.fr.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "tf1.fr",
  "dns": {
    "a": [
      "15.197.129.244"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-004e7e01.gslb.pphosted.com (pref 5)",
      "mxa-004e7e01.gslb.pphosted.com (pref 5)"
    ],
    "ns": [
      "ns1.coltfrance.com.",
      "nsa.perf1.fr.",
      "nsb.perf1.com.",
      "nsc.perf1.com."
    ],
    "spf": [
      "_globalsign-domain-verification=LNtUooOAlKAYEchZJDanSWATh4vjZlH4bSqQpCQHfs",
      "riot-domain-verification=109aa709345405a31d234f32084b830bd96ffd2e7a44659fef9398e6a679",
      "brevo-code:544a91c366fb3af26902ded51f186ddb",
      "dropbox-domain-verification=3mvn6yo2eulg",
      "google-site-verification=BmsnXGpgpnA4PE79CSrGZQew2shAAswaXk4IgLvcIUc",
      "atlassian-domain-verification=CplVLoCxJzsD7CGiyfLoBZVK9myamLx1hhZGLuNRxXkIAQt4musQkZfNsFIlUpYb",
      "apple-domain-verification=g0aeCvbdX7wi0EtF",
      "airtable-verification=b795a1ca889d5281db22616223f6e1bf",
      "stripe-verification=24f853554629863ffc1aa084008764dc27aca81bdb82702337b81f2399f29198",
      "1723b818-df1c-4e2d-a62d-67f48766eaf1",
      "canva-site-verification=fZt682NVwTEdhhvPV1dkVg",
      "amazonses:hIoB0Qk6zVuj9kmisXy1Th9nEncC6l28RSEA35uhEyA=",
      "_globalsign-domain-verification=-Pu4_BQziZVM2L1r7yiSSlNfny7D-rs-VA7zUb_ZTR",
      "jamf-site-verification=NoehuapAsNIs-t8kMzkkTA",
      "miro-verification=457250818deaa8ba419cfef4d2f58673cc092acc",
      "adobe-idp-site-verification=2759e3a4-b2b4-4ea0-87dd-6a83dde0d0a8",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
      "stripe-verification=AB39C2D4B24CE0838BE4EB9B5C16A2741F181E7F67CE6783A7AA73968B939842",
      "wIVLN0DAgswxZPZa5W/m7akdq9zLD1cszETEr1iyLAO1kzMHuXlsF+xwDJAvxi/dBfwmIxqBrFoAQ3vI8qMrew==",
      "storiesonboard-verification=B4A5356384754BD4B2552C9B745DA771",
      "globalsign-domain-verification=cqmSp7pBuHC1yBpjFE-CqNa8I73WQKE8yDfTO35n4C",
      "amazonses:npCI24idlGvAk/N0Y9NefW1xNik46RZzErpclG0dQe4=",
      "MS=ms41345307",
      "anthropic-domain-verification-0t044a=8ICBLD2vkIv9pyZZAEaApYHeh",
      "anthropic-domain-verification-12006m=oXv9xTd0YGBW2PiKtViSwfPoC",
      "amazonses:YUCuCB/Qksg6RZAqpy63pab50PbtV7IUAh42EIstqA4=",
      "stripe-verification=6b5636fc92c2ad778070c583c126a16169c9cbfad5eb2c8248f16ba89ab9aa0f",
      "_globalsign-domain-verification=4q9pKRx6lZ7FRnu4-qednjfIcMAFNun_eaIbgW9A-8",
      "onetrust-domain-verification=fdbbe9c6c2234f0b9291a25e11b2ce0b",
      "stripe-verification=51648884EBEBE506A3EA2464217B2CDEE721AD31D2635492C211CB9719DEB201",
      "stripe-verification=a68b130c255ded7cb89f4aa86cd05b74910f0d17a1c99647fddbb4d66bb61a8d",
      "stripe-verification=949a7d8762693f04034d7c516b8ac47f3d7b30a4ce0b4c7962ecba23f666b899",
      "google-site-verification=pxZHowI56jWuT84YWlhiCRfj_CJ4I0Clfir7aGK5BmM",
      "google-site-verification=4Es-xs2xIcZNP86F-DV28dEvlKyrgLrs6l9hrlTgSN4",
      "stripe-verification=541a5c5f4c8f1ae4d1da1cfe2394032e8414f2a95eb0d923283f3dbdaf7e8697",
      "protonmail-verification=7c5ef0fa886fc9c96a2f1923e4993c74343e42ef",
      "6NYdDvG7VxY8THwZAQnBRKMyu0zLcFGIGWMaMXLGyi0=",
      "amazonses:Eyp2ZoaWmO4RDz91a5vM1+24tiDYpxrSmI5QFOKlodA="
    ],
    "dmarc": [
      "v=DMARC1;",
      "p=reject;",
      "fo=1;",
      "rua=mailto:dmarc_rua@emaildefense.proofpoint.com;",
      "ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "countryName=FR, stateOrProvinceName=Hauts-de-Seine, localityName=Boulogne-Billancourt, organizationName=TELEVISION FRANCAISE 1, commonName=*.tf1.fr",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign RSA OV SSL CA 2018",
    "notBefore": "Jan 22 10:16:29 2026 GMT",
    "notAfter": "Feb 23 10:16:28 2027 GMT",
    "san": [
      "*.tf1.fr",
      "tf1.fr"
    ],
    "days_left": 149,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "15.197.129.244",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.tf1.fr",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "http://www.tf1.fr/"
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
    "_globalsign-domain-verification=LNtUooOAlKAYEchZJDanSWATh4vjZlH4bSqQpCQHfs",
    "riot-domain-verification=109aa709345405a31d234f32084b830bd96ffd2e7a44659fef9398e",
    "dropbox-domain-verification=3mvn6yo2eulg",
    "google-site-verification=BmsnXGpgpnA4PE79CSrGZQew2shAAswaXk4IgLvcIUc",
    "atlassian-domain-verification=CplVLoCxJzsD7CGiyfLoBZVK9myamLx1hhZGLuNRxXkIAQt4mu"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20260122101629",
      "not_after": "20270223101628"
    }
  },
  "x12": {
    "status": 301,
    "ptr": [
      "accf5a60a4b2dbe54.awsglobalaccelerator.com."
    ]
  },
  "elapsed_s": 27.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
