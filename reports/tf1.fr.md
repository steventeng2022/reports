# Security Audit Report — tf1.fr

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://tf1.fr/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | tf1.fr |
| Test date | 2026-09-27 00:33 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

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
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 18 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |

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
- **Detail:** Apex TXT records with verification/token content: airtable-verification=b795a1ca889d5281db22616223f6e1bf; atlassian-domain-verification=CplVLoCxJzsD7CGiyfLoBZVK9myamLx1hhZGLuNRxXkIAQt4mu; stripe-verification=949a7d8762693f04034d7c516b8ac47f3d7b30a4ce0b4c7962ecba23f666
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 15.197.129.244 carries PTR accf5a60a4b2dbe54.awsglobalaccelerator.com. for tf1.fr.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for tf1.fr, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 18. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The tf1.fr certificate lists an AIA OCSP responder (http://ocsp.globalsign.com/gsrsaovsslca2018) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

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
      "nsc.perf1.com.",
      "nsa.perf1.fr.",
      "ns1.coltfrance.com.",
      "nsb.perf1.com."
    ],
    "caa": [],
    "spf": [
      "airtable-verification=b795a1ca889d5281db22616223f6e1bf",
      "atlassian-domain-verification=CplVLoCxJzsD7CGiyfLoBZVK9myamLx1hhZGLuNRxXkIAQt4musQkZfNsFIlUpYb",
      "stripe-verification=949a7d8762693f04034d7c516b8ac47f3d7b30a4ce0b4c7962ecba23f666b899",
      "canva-site-verification=fZt682NVwTEdhhvPV1dkVg",
      "stripe-verification=AB39C2D4B24CE0838BE4EB9B5C16A2741F181E7F67CE6783A7AA73968B939842",
      "globalsign-domain-verification=cqmSp7pBuHC1yBpjFE-CqNa8I73WQKE8yDfTO35n4C",
      "protonmail-verification=7c5ef0fa886fc9c96a2f1923e4993c74343e42ef",
      "stripe-verification=541a5c5f4c8f1ae4d1da1cfe2394032e8414f2a95eb0d923283f3dbdaf7e8697",
      "1723b818-df1c-4e2d-a62d-67f48766eaf1",
      "amazonses:hIoB0Qk6zVuj9kmisXy1Th9nEncC6l28RSEA35uhEyA=",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
      "_globalsign-domain-verification=LNtUooOAlKAYEchZJDanSWATh4vjZlH4bSqQpCQHfs",
      "stripe-verification=6b5636fc92c2ad778070c583c126a16169c9cbfad5eb2c8248f16ba89ab9aa0f",
      "adobe-idp-site-verification=2759e3a4-b2b4-4ea0-87dd-6a83dde0d0a8",
      "amazonses:YUCuCB/Qksg6RZAqpy63pab50PbtV7IUAh42EIstqA4=",
      "stripe-verification=51648884EBEBE506A3EA2464217B2CDEE721AD31D2635492C211CB9719DEB201",
      "anthropic-domain-verification-12006m=oXv9xTd0YGBW2PiKtViSwfPoC",
      "_globalsign-domain-verification=-Pu4_BQziZVM2L1r7yiSSlNfny7D-rs-VA7zUb_ZTR",
      "amazonses:Eyp2ZoaWmO4RDz91a5vM1+24tiDYpxrSmI5QFOKlodA=",
      "6NYdDvG7VxY8THwZAQnBRKMyu0zLcFGIGWMaMXLGyi0=",
      "jamf-site-verification=NoehuapAsNIs-t8kMzkkTA",
      "stripe-verification=24f853554629863ffc1aa084008764dc27aca81bdb82702337b81f2399f29198",
      "google-site-verification=BmsnXGpgpnA4PE79CSrGZQew2shAAswaXk4IgLvcIUc",
      "google-site-verification=pxZHowI56jWuT84YWlhiCRfj_CJ4I0Clfir7aGK5BmM",
      "wIVLN0DAgswxZPZa5W/m7akdq9zLD1cszETEr1iyLAO1kzMHuXlsF+xwDJAvxi/dBfwmIxqBrFoAQ3vI8qMrew==",
      "miro-verification=457250818deaa8ba419cfef4d2f58673cc092acc",
      "riot-domain-verification=109aa709345405a31d234f32084b830bd96ffd2e7a44659fef9398e6a679",
      "amazonses:npCI24idlGvAk/N0Y9NefW1xNik46RZzErpclG0dQe4=",
      "stripe-verification=a68b130c255ded7cb89f4aa86cd05b74910f0d17a1c99647fddbb4d66bb61a8d",
      "onetrust-domain-verification=fdbbe9c6c2234f0b9291a25e11b2ce0b",
      "MS=ms41345307",
      "storiesonboard-verification=B4A5356384754BD4B2552C9B745DA771",
      "anthropic-domain-verification-0t044a=8ICBLD2vkIv9pyZZAEaApYHeh",
      "_globalsign-domain-verification=4q9pKRx6lZ7FRnu4-qednjfIcMAFNun_eaIbgW9A-8",
      "brevo-code:544a91c366fb3af26902ded51f186ddb",
      "google-site-verification=4Es-xs2xIcZNP86F-DV28dEvlKyrgLrs6l9hrlTgSN4",
      "apple-domain-verification=g0aeCvbdX7wi0EtF",
      "dropbox-domain-verification=3mvn6yo2eulg"
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
    "airtable-verification=b795a1ca889d5281db22616223f6e1bf",
    "atlassian-domain-verification=CplVLoCxJzsD7CGiyfLoBZVK9myamLx1hhZGLuNRxXkIAQt4mu",
    "stripe-verification=949a7d8762693f04034d7c516b8ac47f3d7b30a4ce0b4c7962ecba23f666",
    "canva-site-verification=fZt682NVwTEdhhvPV1dkVg",
    "stripe-verification=AB39C2D4B24CE0838BE4EB9B5C16A2741F181E7F67CE6783A7AA73968B93"
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
      "aia_ocsp": "http://ocsp.globalsign.com/gsrsaovsslca2018",
      "serial": 12758277588344137667138567892,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": null,
      "subject_dn": "310b3009060355040613024652311730150603550408130e48617574732d64652d5365696e65311d301b06035504071314426f756c6f676e652d42696c6c616e636f757274311f301d060355040a131654454c45564953494f4e204652414e434149534520313111300f06035504030c082a2e7466312e6672",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312630240603550403131d476c6f62616c5369676e20525341204f562053534c2043412032303138",
      "not_before": "20260122101629",
      "not_after": "20270223101628"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 301,
    "ptr": [
      "accf5a60a4b2dbe54.awsglobalaccelerator.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.tf1.fr/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "cipher_ver": "TLSv1.2",
    "root_status": 301
  },
  "elapsed_s": 41.3,
  "rechecked": "2026-09-27 00:08 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- re-run #15 passive additions: TLS 1.0/1.1, cipher-suite and key-exchange observations come from the handshake the base TLS check already performed plus one quiet re-handshake with no HTTP traffic; HTML-level angles read the root document already fetched for header checks; the only extra request this pass is a read-only GET to /.well-known/openid-configuration (plus the earlier passes' security.txt, sitemap.xml and CRL GETs).
- Findings are reported against the public program scope; submission through the program tracker is pending.
