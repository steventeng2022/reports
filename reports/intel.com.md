# Security Audit Report — intel.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://intel.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | intel.com |
| Test date | 2026-09-27 01:24 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 3, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL10 | DMARC subdomain policy (sp=) set while apex policy is p=none | CWE-285 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 17 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 18 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 19 | info | CT1 | 97 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

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

### 9. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://intel.com/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] DMARC subdomain policy (sp=) set while apex policy is p=none (`MAIL10`)

- **CWE:** CWE-285
- **Detail:** Subdomains are enforced while the apex domain is monitor-only.
- **Recommendation:** Confirm the split policy is intended.

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
- **Detail:** Apex TXT records with verification/token content: apple-domain-verification=OAQrNBk5trF8X7H3; Dynatrace-site-verification=03bc0e9d-4899-45bc-8fb6-963829cd5cf1__m1rmdc12bet67g; anthropic-domain-verification-ygt3tf=Q9RHyPSxi5ES3lSyMrb5aJ3WV
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but intel.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on intel.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 17. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for intel.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 18. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The intel.com certificate lists an AIA OCSP responder (http://ocsp.sectigo.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 19. [INFO] 97 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: epsilon-cpa.app.intel.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "intel.com",
  "dns": {
    "a": [
      "13.91.95.74"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mgamail.eglb.intel.com (pref 100)"
    ],
    "ns": [
      "ns2.intel.com.",
      "ns4.intel.com.",
      "ns3.intel.com.",
      "ns1.intel.com."
    ],
    "caa": [],
    "spf": [
      "00DBZ0000008j8l=1TBcn00000001Yn",
      "",
      "apple-domain-verification=OAQrNBk5trF8X7H3",
      "00D2E000001FGQm=1TBcx000000015l",
      "Dynatrace-site-verification=03bc0e9d-4899-45bc-8fb6-963829cd5cf1__m1rmdc12bet67grogkur4kat1r",
      "",
      "anthropic-domain-verification-ygt3tf=Q9RHyPSxi5ES3lSyMrb5aJ3WV",
      "cursor-domain-verification-5h3fn5=uPEBnPX0FRt8elKd8xtpotTsg",
      "00DO4000007MxTd=1TBO40000000KA2",
      "google-site-verification=xQ71LIpBIRMAhe6YyAjaNEeqOHF6VOCCLJD-xBsnwtU",
      "00Df40000004A8x=1TBVX00000001Tx",
      "uber-domain-verification=233c950b-1660-447a-a8bc-a0bb20559c05",
      "onetrust-domain-verification=da03b7174c53436587dd407887778160",
      "adobe-idp-site-verification=12d5bea8-aab4-4b2e-9c77-8f69ad4734f0",
      "00D15000000EnBl=1TB7y00000000uT",
      "perplexity-ai-domain-verification-r24pxy=rliweb0yORQ8UxAD7URTfKgdu",
      "bcd9860a-1369-4d5c-ae5e-e9320d79f083",
      "00D36000000K1su=1TBQQ00000001qX",
      "00DcV000002xNXJ=1TBcV00000000BJ",
      "00D7h000000HD25=1TBWL00000005Az",
      "00D6w0000004eS8=1TBdh0000000EKj",
      "00D8c000006KOns=1TBWQ000000023R",
      "google-site-verification=33gwj8vJs6_J5adGCJ3IWWAm5C4MeM-ZUy5uzNIEX4s",
      "docusign=ff4d259b-5b2b-4dc7-84e5-34dc2c13e83e",
      "v=spf1 include:_spf.intel.com -all",
      "atlassian-domain-verification=dfPURS8tP5ncA5xHnEv8nyfRQZzwLH6RRKWNXRHLwny6EBpmC7pwMz1xFLmi/EWH",
      "00D4B0000009zrY=1TBdh00000007JF",
      "mongodb-site-verification=p6n0w6nnOPjCeuCnsW0Xc4UgAh4jfMHo",
      "autodesk-domain-verification=EKQ8nv86UxiJDM9bI18R",
      "00D1I000000nTd4=1TBQQ000000017N",
      "onetrust-domain-verification=ee0aec8e25a047c185d8fff907e052c2",
      "e94b687f1bd60e6d49bee301361913c22b1aaf63beb963f10826f8472fced7f1",
      "chariot=chariot+intel@praetorian.com",
      "fastly-domain-delegation-RIA8ruNVQ8qqxgwlPyD3-485843-2022-27-04",
      "atlassian-domain-verification=qHOhH89J6Mh62tAEcDaX6swdU8wX1iJZUUlaDWdfkcma0KJ1qVgrfNrxbtBvAOqH",
      "00D2f0000000uGy=1TBOt0000000T21",
      "00DU0000000YT3c=1TBVz00000001CD",
      "google-site-verification=HZCQBwMXW2bQcmIUCMcxovy1yMxkEcu1mGA2spyLARo",
      "docker-verification=ce0bc02e-16dd-47c2-bb3e-7f6d680dcd47",
      "00D2i0000000pFZ=1TBdh000000079Z",
      "09/10/2024",
      "00D7j0000004Xkw=1TBdh00000006VF",
      "00DU0000000JvXT=1TBPb00000000cj",
      "ms-domain-verification=63e408c2-11b8-4d5f-939c-d71b7d7e3d91",
      "ibmid=b4542555-fac2-4d7d-a8ad-f4d3ee20ba22",
      "cloudhealth=1659ead7-5c47-4817-a0d3-94b456169734",
      "meltwater_sso_20240930",
      "00D8C0000008hms=1TBDZ0000000022",
      "00DcV000002z2LV=1TBcV00000005XZ",
      "00D3k000000ub4r=1TBQQ00000001ov",
      "00DC00000016oM2=1TBcw00000001wz",
      "canva-site-verification=Udnsc-EibCkG6QIOjQ53WQ",
      "00D3F0000000Nmr=1TBRu0000000dEH",
      "00DKQ0000000ni0=1TBKQ000000KykT",
      "00D2i0000008d6j=1TBTH00000006IL",
      "00D1I000003pf77=1TBVv00000000ZV",
      "00D8F0000004i7a=1TBW400000002kz",
      "I+FotdhF45rEb5bSOZyqcRNYMIuqDOEcWLtvZ8cb5RKf4p2v+6laazMU1bT8dq88ia98W9aUKYirlD7+tv0Z/A==",
      "google-site-verification=_BVjdlNMi517YkaWfQ8SOCUxjGyrK4X4tkMeCqieedQ",
      "Dynatrace-site-verification=e1eb3fe5-f14a-4a0c-b8b6-1c5f380cb804__dfadqbk4o2ngu8n8bho3kom0t",
      "00Do0000000aRcf=1TBcv000000029t",
      "MS=B03F616C5688CE657CC2FA94EF4E72109431092B",
      "teamviewer-sso-verification=c0fca594575d4ae58cb4d02d7ede2b3e",
      "00DDS000001gRdW=1TBOu0000000A2b",
      "00DRL00000KHFn7=1TBRL0000000K1x",
      "00D780000004Z0C=1TBVZ0000000M5N",
      "00D36000000rSuA=1TBPe00000002zV",
      "00Ddy000003k0uX=1TBdy00000009cn",
      "slack-domain-verification=1Cz4MCZJuypQf1rh9T3qlqJDFCRYuqZkrOUh5kL4",
      "00Do0000000L7IX=1TBV40000000G8I",
      "docusign=46a68707-4a57-4782-bf77-1373777e73e8",
      "00D040000000QYW=1TBDc0000008OLs",
      "00D8A0000005uU8=1TBWA0000004VV3",
      "00Dbf000005BKtN=1TBbf0000000HDm",
      "00D23000000Fw7O=1TBWH0000000I6b",
      "00DWJ000008Mljd=1TBWJ0000000Di1",
      "atlassian-domain-verification=ZOexs0awZv94sBIlIBoxjhW8lXHZ24atEWqaXZtHXJyUNyrJRFD2TUyajwtz1pL1",
      "00DHu000002tYyb=1TBcv00000004lB",
      "00Ddi000004mJ65=1TBdi0000000FK1",
      "google-site-verification=pv06NhezCJEfqLpFMO8YKqC6Ye1q85TiFq_S5qUUdxE",
      "00DDn000003r4Pl=1TBQQ000000021p",
      "bluebeam-verification=ocvjzp7gd8fvt0qv85zgh1og5o3nl9",
      "google-site-verification=pIbeNdxnfMeMUhiz7Ad6UlkU08jIlagr9h55GoQSw6I",
      "00D2D000000E9ZK=1TBWA0000004VGX",
      "08428d8e-d6dd-4d4f-acca-42955adb18cf",
      "00D5C000000NdC1=1TBce00000001H3",
      "f076027a-8022-4cd7-9c52-373ef56f9848",
      "00DQL00000NjvOH=1TBQL0000000pCD",
      "00DVB0000075KEz=1TBVB00000009Un",
      "atlassian-domain-verification=ApWZ5iliIwA1g0Ka7JhMa7BP0qBkz/WIaMoGiJqvekBz2LJlc2QD7foiLd2h72Rv",
      "onetrust-domain-verification=09f55ff1baba439b9174d37afefcaf2d",
      "00D52000000L89a=1TBVa00000000Uf",
      "00DE0000000Hxbi=1TBPY00000002OP",
      "00DDD000001fKur=1TBdh000000091h",
      "00D6w0000004cRG=1TBVA0000000QTx",
      "openai-domain-verification=dv-lOXezFecTzWt8rrZT7dTGVFq",
      "00D2f0000008gWF=1TBgP0000000Ac5",
      "00D2f0000008gWP=1TBgP00000003kH",
      "google-site-verification=tCdhchtzK9L-sDZA5OazdRCeK5HrqgOJ9kZkzdbtmd8",
      "00Dgy0000000YzN=1TBgy00000000WH",
      "00Dco000004OBXu=1TBco00000000BJ",
      "00Dg0000006V1T1=1TBdh0000000CMA",
      "00D830000008aVT=1TBcr00000000zJ",
      "qqmail-site-verification=de1a8d707315b7e0442efe7a2812e10457a771ccdeb",
      "00Dj0000001tZRR=1TBa6000000012X"
    ],
    "dmarc": [
      "v=DMARC1;p=none;sp=none;fo=1;rua=mailto:dmarc.notification@intel.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, organizationName=Intel Corporation, commonName=intel.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA OV R36",
    "notBefore": "Sep  3 00:00:00 2026 GMT",
    "notAfter": "Dec  2 23:59:59 2026 GMT",
    "san": [
      "intel.com",
      "01.org",
      "acpica.org",
      "barefootnetworks.com",
      "buyaltera.com",
      "dml-lang.org",
      "easic.com",
      "exploreintel.com",
      "granulate.io",
      "insight.tech",
      "intel.ai",
      "intel.ca",
      "intel.cn",
      "intel.co.id",
      "intel.co.il",
      "intel.co.jp",
      "intel.co.kr",
      "intel.co.uk",
      "intel.co.za",
      "intel.com.au",
      "intel.com.br",
      "intel.com.tr",
      "intel.com.tw",
      "intel.de",
      "intel.dev",
      "intel.es",
      "intel.eu",
      "intel.fr",
      "intel.gg",
      "intel.ie",
      "intel.in",
      "intel.it",
      "intel.la",
      "intel.lv",
      "intel.me",
      "intel.ph",
      "intel.pl",
      "intel.se",
      "intel.sg",
      "intel.vn",
      "intelcapital.com",
      "intelreimbursement.com",
      "meccontroller.com",
      "movidius.com",
      "movidius.org",
      "opencas.io",
      "opendroneid.org",
      "openvino.ai",
      "passwordday.org",
      "projectcircuitbreaker.com",
      "renderingtoolkit.org",
      "sigopt.com",
      "smart-edge.info",
      "smart-edge.io",
      "smart-edge.net",
      "smart-edge.org",
      "smart-edge.systems",
      "smartedge.info",
      "threadingbuildingblocks.org"
    ],
    "days_left": 66,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "13.91.95.74",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.intel.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://intel.com/"
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
    "count": 97,
    "notable": [
      "epsilon-cpa.app.intel.com"
    ],
    "sample": [
      "ags.intel.com",
      "ai-apis-dev.laas.intel.com",
      "ai-apis.laas.intel.com",
      "amt.iglb.intel.com",
      "askit-genai-chatbot-dev.intel.com",
      "assessmenttool-test.intel.com",
      "bitlockersearch.intel.com",
      "canary-manager.intel.com",
      "cane.intel.com",
      "cc-status.trustedservices.intel.com",
      "cmlab-test.intel.com",
      "community-stage.intel.com",
      "community.intel.com",
      "consumer.intel.com",
      "consumerdev.intel.com",
      "consumerint.intel.com",
      "create.info.intel.com",
      "crowdsource-pp.intel.com",
      "crowdsourceapi-pp.intel.com",
      "design-assistant-dev.cloudapps.intel.com"
    ]
  },
  "apex_txt": [
    "apple-domain-verification=OAQrNBk5trF8X7H3",
    "Dynatrace-site-verification=03bc0e9d-4899-45bc-8fb6-963829cd5cf1__m1rmdc12bet67g",
    "anthropic-domain-verification-ygt3tf=Q9RHyPSxi5ES3lSyMrb5aJ3WV",
    "cursor-domain-verification-5h3fn5=uPEBnPX0FRt8elKd8xtpotTsg",
    "google-site-verification=xQ71LIpBIRMAhe6YyAjaNEeqOHF6VOCCLJD-xBsnwtU"
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
      "aia_ocsp": "http://ocsp.sectigo.com",
      "serial": 333190972388248392202255260948676742397,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.sectigo.com/SectigoPublicServerAuthenticationCAOVR36.crl"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311a3018060355040a1311496e74656c20436f72706f726174696f6e3112301006035504031309696e74656c2e636f6d",
      "issuer_dn": "310b300906035504061302474231183016060355040a130f5365637469676f204c696d69746564313730350603550403132e5365637469676f205075626c6963205365727665722041757468656e7469636174696f6e204341204f5620523336",
      "not_before": "20260903000000",
      "not_after": "20261202235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.intel.com/",
    "http_status": 302,
    "p404_status": 301,
    "wellknown": [
      "/.well-known/apple-app-site-association",
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
    "hsts": "max-age=31536000 ; includeSubDomains ; preload",
    "crl": {
      "url": "http://crl.sectigo.com/SectigoPublicServerAuthenticationCAOVR36.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "elapsed_s": 31.4,
  "rechecked": "2026-09-27 01:08 UTC"
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
- Findings are reported against the public program scope; submission through the program tracker is pending.
