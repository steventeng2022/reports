# Security Audit Report — amazon.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://amazon.com/ |
| Bug bounty program | Amazon |
| Listed scope domain | amazon.com |
| Test date | 2026-09-27 02:17 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 4, Info: 18)

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
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 20 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 21 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 22 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Server
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
- **Detail:** Header reveals: Server
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=D0RwRb_QApkpApKTFaFlRwbm_yrkey0uokKw0wQUIdk; stripe-verification=a27edc0da55836ea6bb7eac592bf2ca8e246eb652608d54493119df7df00; bluebeam-verification=042eaxvbk65qgh5qom1ajtm4eyuo1k
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 218 disallow path(s), e.g. /exec/obidos/account-access-login, /exec/obidos/change-style, /exec/obidos/flex-sign-in, /exec/obidos/handle-buy-box, /exec/obidos/tg/cm/member/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 98.82.161.185 carries PTR ec2-98-82-161-185.compute-1.amazonaws.com. for amazon.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on amazon.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for amazon.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The amazon.com certificate lists an AIA OCSP responder (http://status.geotrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 20. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of amazon.com contains wildcard SAN entry(ies) *.peg.a2z.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 21. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of amazon.com is http://status.geotrust.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 22. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of amazon.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

## Evidence (raw response observations)

```json
{
  "domain": "amazon.com",
  "dns": {
    "a": [
      "98.82.161.185",
      "98.87.170.74",
      "98.87.170.71"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "amazon-smtp.amazon.com (pref 5)"
    ],
    "ns": [
      "ns-264.awsdns-33.com.",
      "ns-521.awsdns-01.net.",
      "ns-1707.awsdns-21.co.uk.",
      "ns-1447.awsdns-52.org."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=D0RwRb_QApkpApKTFaFlRwbm_yrkey0uokKw0wQUIdk",
      "stripe-verification=a27edc0da55836ea6bb7eac592bf2ca8e246eb652608d54493119df7df005afc",
      "bluebeam-verification=042eaxvbk65qgh5qom1ajtm4eyuo1k",
      "canva-site-verification=Hksh9WEUPWP13_SEU1mPMA",
      "sending_domain229492=7cde83fbc5246557c64d9d9ba79f0d11f7ba9eb6127f60451a9aa6f8dead4381",
      "wrike-verification=MzI3NzM2ODo2NDk5MjE4NjQ2MWJmOTEwMGMxM2MzNzJmNWJlY2U5ZDU4MmVlNzQ2NWU4MTY5OWJjMjlmYjQ4Mjc5M2JiMzky",
      "v=spf1 include:spf1.amazon.com include:spf2.amazon.com include:amazonses.com -all",
      "pardot326621=b26a7b44d7c73d119ef9dfd1a24d93c77d583ac50ba4ecedd899a9134734403b",
      "stripe-verification=8E217BE0FF12B50596BD78EEA3F81E62C6C7A2AC78FBD46DAD95B7D21BA2F8BF",
      "box-domain-verification=ffea95cd0e0d61c302198367155b07e74fd534fa1d867662dc9bf9969b6f535d",
      "apple-domain-verification=_j3fIZD8uuYetbG64YKTEpz-8mwyvYrLRqM5CoVZVTk",
      "stripe-verification=76924B623B7105057C67D4F5EAE19F65EE8BD92635581BCACA2CCACA4D38FE1B",
      "vizcom-domain-verification-Otrns5=NtkDXOBddZZnm9ETuwyrltTdl",
      "spf2.0/pra include:spf1.amazon.com include:spf2.amazon.com include:amazonses.com -all",
      "liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo",
      "ZOOM_verify_ARI4AiKALCcjulAUZNwR8S",
      "stripe-verification=26EFABF97D624D7F4F3C062366A04C4B1399841F23F275DD81E58D00A981979C",
      "stripe-verification=1D421397AAEC571CCBD9F25DDC90F00EDEBC3E74F4047270EC9A13B784579E34",
      "stripe-verification=65883709F0B36AB2B73FFC870338AE9F817315DDBB1CAB28910F074F4A8DE1EC",
      "apple-domain-verification=dVkKZnu17XS0EN2X",
      "stripe-verification=6a5d107aa37465eac2101bb1c725b02072689a4fa7bd38b455970baac4979a17",
      "google-site-verification=G_-mXb0ZYjjGkQVGjpOOB2deSOaVdxVj4i4vozJTREs",
      "stripe-verification=79C640ED20153B836A623F16A3DCF65E2072948FB80C42D19300514DADF94EC5",
      "autodesk-domain-verification=dmryiygGOGBJFJFVo5Bl",
      "canva-site-verification=WhUvTbfe6tUQWmIXnQifGA",
      "uber-domain-verification=0ddb4c64-175c-4e7a-8a7a-f552034222e8",
      "stripe-verification=45f746e3b195198f419af3f685fdf217532ce552b4b47070b3caefe325559a67",
      "sending_domain197572=555e96ed2e576ced81c89f7001740cb72f9c66aeb136d0d05734aad625766bc1",
      "stripe-verification=a5c01aa4d732f4b93154d67983d77982ef1a2db73fecfd4bcd64e224d3ab4075",
      "sending_domain229492=341509a116ea4311fcb2e489303bf09a139b10ce9b90e5029d2677055cb4dc89",
      "MS=4B600B22799EB2CAC0D8FF0A3A3CAECA5EE2BF3A",
      "brevo-code:9be7f7c39958d253a31de6593fa831bc",
      "google-site-verification=NV91qEfNgqDZOPzwlhXE-KtDUfCBSNgAsdxaFebyh80",
      "cisco-ci-domain-verification=1b256bd11daa486ba2fa405d2d5de70f75feb6757dd8993ca8de685a7dfea1df",
      "sending_domain608861=d33a88e8540c33a1217138cf8a25879734bd35673bb7cfbd639f95c550b33ec4",
      "DomainVerification=6BSORJ4NP9YO8U8EZFZDKIJVIL6TCYG69G7CXADQ8QOV3K8883K86XT2J9EX5R0J",
      "sending_domain1003771=f1303d8ee3b86e39db2703b11feb83e1e8b712a9ffc64c3d56505192e5b3bf4f",
      "sending_domain608861=81b0d52095dae60d604e7cbea5e58e1d842f7d950d6673a43feae339b664ca31",
      "sending_domain1003771=199bc63a54ace5d8d5c5d08286af86d7049b4afacb5ef7decd6b22cf9e8d5efb",
      "lucidlink-verification=QG752KJ3CMZAZTZ3ERMX1AXMCG",
      "ZOOM_verify_6OUC1znUonKMCoyMMGyFfX",
      "docker-verification=1779f74e-699a-4d8b-acdc-ce242d73559f",
      "pendo-domain-verification=ecbe1a51-954d-4202-ab86-d15e04b96769",
      "00DcX000002xu6h=1TBcX00000000Xt",
      "pstk-verification-a938892542ffacd51af9339e4755dc1a",
      "uber-domain-verification=5f5cc242-4dbe-4871-b726-bbbe085ff053",
      "uber-domain-verification=7a35217f-6956-41a0-be5c-a28ea2646964",
      "stripe-verification=C7ABA7B41F5AC26E3C397015A34CD46ACD2130DC8DAAFA7F59AAEFEDBC3FA517",
      "dell-technologies-domain-verification=amazon.com_2dc4b285-482d-4948-bf92-16e698f2cab9_1738858526",
      "uber-domain-verification=01e9f567-7b84-45dd-9326-53992a028b40",
      "kahoot-domain-verification=0a79e1c18457eed9572b28cd75792e4bbd220bc69b62d707c1f88e53956348d6",
      "uber-domain-verification=72ffdffb-d431-452c-932e-cd1030d1eb46",
      "sending_domain949422=43d714838567583460e7720e6049505edb8e25c1ef4321419d41bc5255db7ba5",
      "sinch-domain-verification=c484be93-e6bc-4440-8984-621eef43d491",
      "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbDvoGpRaIwj/tgPH",
      "sending_domain949422=99a7b44052aefc4dec2abf56189160824664d2fdac00ca962f4455be62b51d56",
      "neat-pulse-domain-verification-QgvLWLN=f37f2998-0bb3-493b-a3aa-c4ff8f3dce08",
      "TS1760027",
      "stripe-verification=B0AD8DC1918B8A717E5B6A29C2E04594A9872AB05F8DA24CB762BBA0A0487BC6",
      "facebook-domain-verification=d9u57u52gylohx845ogo1axzpywpmq",
      "apple-domain-verification=4wbNaeWvAH0pU1yi",
      "google-site-verification=14WGW2MdNMxchG8PlinF7LgqqE0OwwHqOq0HKhb7rDQ",
      "sending_domain1014172=003846595520e80ec84e8cc47c07e3a71afb855fc743bb92cdec93f88c7a4029",
      "stripe-verification=35A865E5A20C09CD0288F87ACA29DE73FF8A704D21F7310A5AAFF4CB63062E81"
    ],
    "dmarc": [
      "v=DMARC1;",
      "p=quarantine;",
      "pct=100;",
      "rua=mailto:report@dmarc.amazon.com;",
      "ruf=mailto:report@dmarc.amazon.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.peg.a2z.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=GeoTrust TLS RSA CA G1",
    "notBefore": "Sep 20 00:00:00 2026 GMT",
    "notAfter": "Apr  5 23:59:59 2027 GMT",
    "san": [
      "amazon.co.uk",
      "uedata.amazon.co.uk",
      "www.amazon.co.uk",
      "origin-www.amazon.co.uk",
      "*.peg.a2z.com",
      "amazon.com",
      "amzn.com",
      "uedata.amazon.com",
      "us.amazon.com",
      "www.amazon.com",
      "www.amzn.com",
      "corporate.amazon.com",
      "buybox.amazon.com",
      "iphone.amazon.com",
      "yp.amazon.com",
      "home.amazon.com",
      "origin-www.amazon.com",
      "origin2-www.amazon.com",
      "buckeye-retail-website.amazon.com",
      "huddles.amazon.com",
      "amazon.de",
      "www.amazon.de",
      "origin-www.amazon.de",
      "amazon.co.jp",
      "amazon.jp",
      "www.amazon.jp",
      "www.amazon.co.jp",
      "origin-www.amazon.co.jp",
      "*.aa.peg.a2z.com",
      "*.ab.peg.a2z.com",
      "*.ac.peg.a2z.com",
      "origin-www.amazon.com.au",
      "www.amazon.com.au",
      "*.bz.peg.a2z.com",
      "amazon.com.au",
      "origin2-www.amazon.co.jp",
      "edgeflow.aero.4d5ad1d2b-frontier.amazon.co.jp",
      "edgeflow.aero.04f01a85e-frontier.amazon.com.au",
      "edgeflow.aero.47cf2c8c9-frontier.amazon.com",
      "edgeflow.aero.abe2c2f23-frontier.amazon.de",
      "edgeflow.aero.bfbdc3ca1-frontier.amazon.co.uk",
      "edgeflow-dp.aero.4d5ad1d2b-frontier.amazon.co.jp",
      "edgeflow-dp.aero.04f01a85e-frontier.amazon.com.au",
      "edgeflow-dp.aero.47cf2c8c9-frontier.amazon.com",
      "edgeflow-dp.aero.bfbdc3ca1-frontier.amazon.co.uk",
      "edgeflow-dp.aero.abe2c2f23-frontier.amazon.de",
      "shop.business.amazon.com"
    ],
    "days_left": 190,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "98.82.161.185",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Server"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.amazon.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://amazon.com/"
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
    "google-site-verification=D0RwRb_QApkpApKTFaFlRwbm_yrkey0uokKw0wQUIdk",
    "stripe-verification=a27edc0da55836ea6bb7eac592bf2ca8e246eb652608d54493119df7df00",
    "bluebeam-verification=042eaxvbk65qgh5qom1ajtm4eyuo1k",
    "canva-site-verification=Hksh9WEUPWP13_SEU1mPMA",
    "wrike-verification=MzI3NzM2ODo2NDk5MjE4NjQ2MWJmOTEwMGMxM2MzNzJmNWJlY2U5ZDU4MmVlN"
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
      "aia_ocsp": "http://status.geotrust.com",
      "serial": 7155697021029473683065491393650584458,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl"
      ],
      "san": [
        "amazon.co.uk",
        "uedata.amazon.co.uk",
        "www.amazon.co.uk",
        "origin-www.amazon.co.uk",
        "*.peg.a2z.com",
        "amazon.com",
        "amzn.com",
        "uedata.amazon.com",
        "us.amazon.com",
        "www.amazon.com",
        "www.amzn.com",
        "corporate.amazon.com",
        "buybox.amazon.com",
        "iphone.amazon.com",
        "yp.amazon.com",
        "home.amazon.com",
        "origin-www.amazon.com",
        "origin2-www.amazon.com",
        "buckeye-retail-website.amazon.com",
        "huddles.amazon.com"
      ],
      "subject_dn": "3116301406035504030c0d2a2e7065672e61327a2e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d311f301d0603550403131647656f547275737420544c5320525341204341204731",
      "not_before": "20260920000000",
      "not_after": "20270405235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/exec/obidos/account-access-login",
      "/exec/obidos/change-style",
      "/exec/obidos/flex-sign-in",
      "/exec/obidos/handle-buy-box",
      "/exec/obidos/tg/cm/member/",
      "/gp/aw/help/id=sss",
      "/gp/cart",
      "/gp/flex",
      "/gp/product/e-mail-friend",
      "/gp/product/product-availability",
      "/gp/product/rate-this-item",
      "/gp/sign-in",
      "/gp/reader",
      "/gp/sitbv3/reader",
      "/gp/richpub/syltguides/create"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-98-82-161-185.compute-1.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.amazon.com/",
    "http_status": 301,
    "p404_status": 301,
    "wellknown": [
      "/.well-known/assetlinks.json"
    ],
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "crl": {
      "url": "http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "x17": {
    "wildcard_san": [
      "*.peg.a2z.com"
    ],
    "ocsp_http": "http://status.geotrust.com"
  },
  "elapsed_s": 47.1,
  "rechecked": "2026-09-27 02:16 UTC"
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
- re-run #16 passive additions: the edge/protocol angles read the alt-svc, server-timing and CDN-identification headers from the one root GET; the preconnect/dns-prefetch, base-href and noindex angles parse the already-fetched root document; the TLS 1.2-only ceiling, SHA-1 signature and weak-key angles use the certificate evidence the base TLS check already captured; the only extra requests this pass are two read-only GETs (/.well-known/jwks.json and /.well-known/change-password).
- re-run #17 passive additions: the retired-header angles (Public-Key-Pins, Expect-CT, X-Permitted-Cross-Domain-Policies, Via, COOP/COEP, Permissions-Policy) read from the one root GET; the wildcard SAN, http:// OCSP and 398-day-cap angles use the certificate evidence the base TLS check already captured (SAN now harvested from the existing DER); the only extra requests this pass are three read-only GETs (/.well-known/dpop-jwks.json, /.well-known/origin-rsa-keys.json, /.well-known/llms.txt).
- Findings are reported against the public program scope; submission through the program tracker is pending.
