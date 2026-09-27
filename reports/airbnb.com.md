# Security Audit Report — airbnb.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://airbnb.com/ |
| Bug bounty program | Airbnb |
| Listed scope domain | airbnb.com |
| Test date | 2026-09-27 02:17 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 4, Info: 18)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 18 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 19 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |
| 20 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 21 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |
| 22 | info | CT1 | 249 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 25 days (notAfter Oct 22 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
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
- **Detail:** Header reveals: nginx
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
- **Detail:** Apex TXT records with verification/token content: webexdomainverification.=162d362c-c218-48f0-8b53-0017116e6f29; google-site-verification=A8e2zY9GYwx8D7x0aOz09Vl4gHfPmv86y_TbW1TUDqs; anthropic-domain-verification-2s2h87=NaRxcN9zTtIb3insUyX7U264A
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 687 disallow path(s), e.g. /.well-known/assetlinks.json, /*/skeleton, /*/sw_skeleton, /500, /account
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 166.117.189.176 carries PTR a333dda39e3b496ea.awsglobalaccelerator.com. for airbnb.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on airbnb.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 18. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The airbnb.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 19. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to airbnb.com negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

### 20. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of airbnb.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 21. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of airbnb.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

### 22. [INFO] 249 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.airbnb.com, admin.dev.staging.airbnb.com, api.airbnb.com, api.akamai-ci.airbnb.com, api.akamai-dev.airbnb.com, api.dev.staging.airbnb.com, api.preprod.airbnb.com, careers.airbnb.com, careers.next.airbnb.com, dev.staging.airbnb.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "airbnb.com",
  "dns": {
    "a": [
      "166.117.189.176",
      "166.117.27.62"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-1453.awsdns-53.org.",
      "ns-558.awsdns-05.net.",
      "dns2.p08.nsone.net.",
      "dns1.p08.nsone.net.",
      "ns-474.awsdns-59.com.",
      "dns4.p08.nsone.net.",
      "dns3.p08.nsone.net.",
      "ns-1932.awsdns-49.co.uk."
    ],
    "caa": [
      "0 issue \"pki.goog\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"digicert.com\"",
      "0 iodef \"mailto:caa-alerts@airbnb.com\""
    ],
    "spf": [
      "webexdomainverification.=162d362c-c218-48f0-8b53-0017116e6f29",
      "google-site-verification=A8e2zY9GYwx8D7x0aOz09Vl4gHfPmv86y_TbW1TUDqs",
      "anthropic-domain-verification-2s2h87=NaRxcN9zTtIb3insUyX7U264A",
      "openai-domain-verification=dv-g8FeEwzIIZCUjUpPuF8szG3a",
      "google-site-verification=Dz--VdnW2R_4K45T0eM8i0vNpFlip_o10WidHL5a3cg",
      "paloaltonetworks-site-verification=4df1258d8366090409f33305a49c27e5e867aa6dfd8d8d936c60bdee3396ee04",
      "status-page-domain-verification=tb81t2ndk8pb",
      "yahoo-verification-key=YbxdxsyS96Uy5zQpwbZnLfjBY3tMlG2qWTSLHvVrsZ8=",
      "miro-verification=c5c6890aa37542fb59662ade09a0778c6e028b2f",
      "webexdomainverification.725890277b499457e053ab06fc0a5ef4=b060825b-4db4-4ce3-a61e-debc56370fc0",
      "v=spf1 include:spf1.airbnb.com ip6:2c0f:fb50:4864::/56 ip6:2a00:1450:4864::/56 ip6:2800:3f0:4864::/56 ip6:2607:f8b0:4864::/56 ip6:2404:6800:4864::/56 ip6:2001:4860:4864::/56 ip4:98.77.0.0/16 ip4:87.253.232.0/21 ip4:76.223.176.0/20 ip4:76.223.128.0/19 -all",
      "docusign=1c606b88-26ef-48f9-8913-a4251a947532",
      "gradle-verification=VV7U686RA4HKV4QKVJ4L85Q6V6CJ6",
      "google-site-verification=_e6Ayd8GN0S5dR116WkaM5ds5tx3ekRD5DC9-51pGrg",
      "neat-pulse-domain-verification-Kkvm4PN=ab046095-265e-45ae-8816-c61097444bfd",
      "ecostruxure-it-verification=5dd49b15-5fc0-4967-914f-3cc7b2fd6cdf",
      "lucidlink-verification=B2MS39YZ6H92VYF0X75CJHKRC4",
      "canva-site-verification=LTDCDSi1WalQaoEcq8B1WA",
      "adobe-idp-site-verification=e68ae64c-3a65-4439-b368-0042e72c4cc8",
      "masv=MDSVaBxDxTKiIngeAbltVvdnlTkAhnci",
      "google-site-verification=EFtD_37EY5f55YpAvM8rJ-e6Mwi1I3HF9Xuym2-ZlY8",
      "MS=ms85621737",
      "datadome-domain-verify=W7kEoUrcETDB4afh6Dg5XcjzGWIxidID",
      "bettercomp-verify=2b6685a8a6a942417057188531c867db5c85bc8aa25f038a77784e6f0f8bc84f",
      "dtm-domain-verification=pKWJVhJM8WfWtDBjyfKZjwxGurB9fiCf1TpvWO_Kvmw",
      "wework-site-verification=pnT3RXj0097aqZvB",
      "elevenlabs=igH15TA-6-8aXgxhsL6--iDut7kibGkXsl3Qrvth8gY",
      "DirectFedAuthUrl=https://airbnb.okta.com/app/airbnb_pwcprodnewhiddensaml_1/exk223q4dm1BiHGe81d8/sso/saml",
      "cisco-ci-domain-verification=eef9c0a839b89aed57cdd00866d163bb0660fec297c0c1e4b275baec96cfa10",
      "segment-site-verification=ZkxkEuKJrGI9MrWGC0qw795Xkj9ZlcBq",
      "1password-site-verification=2UO5LR7CZBAKBDNJPUTRIFTUJM",
      "google-site-verification=HEoQR0xvby-BYv7pNt06jkvTF44l6rvMnREUZSTyfYQ",
      "facebook-domain-verification=t3zulila9jjnrfbyt6vjamhqdxz47f",
      "docusign=d56dee1c-0384-4ffa-8801-e6bea308af97",
      "atlassian-domain-verification=mvMbea0qZ4IoMr8/xjkRYgjiHikXBbF04PZnZYv1Nj9UgppCnagnNaSo4T8QnCnP",
      "reejig-platform-domain-verification-0dc5cd=a9i760YDrujxnHMEEoXwZP5bD",
      "rzp-site-verification=31fa3e1cd566e8d7347ed9bb16424c59",
      "status-page-domain-verification=vxdvtv6jn2y9",
      "apple-domain-verification=KVJVb0VKHY0IkzDH",
      "stripe-verification=271cb9609512aa1a36ff5693b0a5cd9f04d19e089e8abae29dde633abc19749d"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;sp=reject;pct=100;ruf=mailto:dmarc.forensic@airbnb.com;rua=mailto:dmarc.aggregate@airbnb.com;aspf=r;adkim=r;fo=1;ri=3600"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Francisco, organizationName=Airbnb, Inc., commonName=airbnb.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jun 25 00:00:00 2026 GMT",
    "notAfter": "Oct 22 23:59:59 2026 GMT",
    "san": [
      "airbnb.com",
      "airbnb.at",
      "airbnb.com.mt",
      "airbnb.com.ar",
      "airbnb.com.ee",
      "airbnb.com.ph",
      "dr.airbnb.com",
      "airbnb.dk",
      "airbnb.com.py",
      "airbnb.com.co",
      "airbnb.rs",
      "airbnb.lu",
      "airbnb.co.uk",
      "airbnb.jp",
      "airbnb.co.za",
      "airbnb.co.nz",
      "airbnb.is",
      "airbnb.cz",
      "airbnb.co.in",
      "airbnb.lv",
      "airbnb.ba",
      "airbnb.com.bz",
      "airbnb.es",
      "airbnb.am",
      "airbnb.pl",
      "airbnb.gy",
      "airbnb.se",
      "airbnb.com.br",
      "airbnb.com.ni",
      "airbnb.cl",
      "airbnb.co.il",
      "airbnb.com.ec",
      "airbnb.com.ua",
      "airbnb.com.hn",
      "airbnb.com.sv",
      "airbnb.org",
      "airbnb.ca",
      "airbnb.pt",
      "airbnb.fr",
      "airbnb.be",
      "airbnb.de",
      "airbnb.hu",
      "airbnb.lt",
      "airbnb.com.gt",
      "airbnb.no",
      "airbnb.az",
      "airbnb.com.hk",
      "airbnb.si",
      "airbnb.com.ro",
      "airbnb.co.cr",
      "airbnb.me",
      "airbnb.gr",
      "airbnb.com.bo",
      "airbnb.com.tr",
      "airbnb.com.au",
      "airbnb.com.vn",
      "airbnb.co.kr",
      "airbnb.la",
      "airbnb.co.ve",
      "airbnb.cat",
      "airbnb.com.hr",
      "airbnb.com.kh",
      "airbnb.com.my",
      "airbnb.fi",
      "airbnb.ae",
      "airbnb.com.sg",
      "airbnb.ch",
      "airbnb.com.pa",
      "airbnb.it",
      "airbnb.mx",
      "airbnb.com.pe",
      "airbnb.com.tw",
      "airbnb.cn",
      "airbnb.ie",
      "airbnb.co.id",
      "airbnb.al",
      "airbnb.tools",
      "airbnb.nl"
    ],
    "days_left": 25,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "166.117.189.176",
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
      "origin": "https://sub.airbnb.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://airbnb.com/"
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
    "source": "certspotter",
    "count": 249,
    "notable": [
      "admin.airbnb.com",
      "admin.dev.staging.airbnb.com",
      "api.airbnb.com",
      "api.akamai-ci.airbnb.com",
      "api.akamai-dev.airbnb.com",
      "api.dev.staging.airbnb.com",
      "api.preprod.airbnb.com",
      "careers.airbnb.com",
      "careers.next.airbnb.com",
      "dev.staging.airbnb.com",
      "git.airbnb.com",
      "grafana.iac-dev.airbnb.com",
      "grafana.iac.airbnb.com",
      "hr.airbnb.com",
      "hr.next.airbnb.com"
    ],
    "sample": [
      "8c9be.airbnb.com",
      "admin-lite-next.airbnb.com",
      "admin-lite-staging.airbnb.com",
      "admin-lite.airbnb.com",
      "admin-next.airbnb.com",
      "admin-staging.airbnb.com",
      "admin.airbnb.com",
      "admin.dev.staging.airbnb.com",
      "airbnb.com",
      "akamai-staging.airbnb.com",
      "amex-mtls-staging.airbnb.com",
      "amex-mtls.airbnb.com",
      "api.airbnb.com",
      "api.akamai-ci.airbnb.com",
      "api.akamai-dev.airbnb.com",
      "api.dev.staging.airbnb.com",
      "api.preprod.airbnb.com",
      "ar.airbnb.com",
      "ar.next.airbnb.com",
      "az.airbnb.com"
    ]
  },
  "apex_txt": [
    "webexdomainverification.=162d362c-c218-48f0-8b53-0017116e6f29",
    "google-site-verification=A8e2zY9GYwx8D7x0aOz09Vl4gHfPmv86y_TbW1TUDqs",
    "anthropic-domain-verification-2s2h87=NaRxcN9zTtIb3insUyX7U264A",
    "openai-domain-verification=dv-g8FeEwzIIZCUjUpPuF8szG3a",
    "google-site-verification=Dz--VdnW2R_4K45T0eM8i0vNpFlip_o10WidHL5a3cg"
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
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 14515940523650229018714061638195266956,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "san": [
        "airbnb.com",
        "airbnb.at",
        "airbnb.com.mt",
        "airbnb.com.ar",
        "airbnb.com.ee",
        "airbnb.com.ph",
        "dr.airbnb.com",
        "airbnb.dk",
        "airbnb.com.py",
        "airbnb.com.co",
        "airbnb.rs",
        "airbnb.lu",
        "airbnb.co.uk",
        "airbnb.jp",
        "airbnb.co.za",
        "airbnb.co.nz",
        "airbnb.is",
        "airbnb.cz",
        "airbnb.co.in",
        "airbnb.lv"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d53616e204672616e636973636f31153013060355040a130c416972626e622c20496e632e311330110603550403130a616972626e622e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260625000000",
      "not_after": "20261022235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/.well-known/assetlinks.json",
      "/*/skeleton",
      "/*/sw_skeleton",
      "/500",
      "/account",
      "/alumni",
      "/api/v1/trebuchet",
      "/associates/click",
      "/book/",
      "/calendar/",
      "/contact_host",
      "/disaster/lookup",
      "/email/unsubscribe",
      "/embeddable",
      "/experiences/*?*scheduled_id"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a333dda39e3b496ea.awsglobalaccelerator.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.airbnb.com/",
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
    "hsts": "max-age=31536000; includeSubDomains; preload",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "cipher_ver": "TLSv1.2",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "x17": {
    "ocsp_http": "http://ocsp.digicert.com"
  },
  "elapsed_s": 43.3,
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
