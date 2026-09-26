# Security Audit Report — intel.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://intel.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | intel.com |
| Test date | 2026-09-25 07:50 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 3, Info: 8)

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
| 11 | info | CT1 | 97 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 11. [INFO] 97 hostnames found via Certificate Transparency (certspotter) (`CT1`)

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
      "ns1.intel.com.",
      "ns3.intel.com.",
      "ns2.intel.com.",
      "ns4.intel.com."
    ],
    "spf": [
      "00D8F0000004i7a=1TBW400000002kz",
      "ibmid=b4542555-fac2-4d7d-a8ad-f4d3ee20ba22",
      "00D2f0000008gWF=1TBgP0000000Ac5",
      "00D6w0000004eS8=1TBdh0000000EKj",
      "00D2f0000000uGy=1TBOt0000000T21",
      "adobe-idp-site-verification=12d5bea8-aab4-4b2e-9c77-8f69ad4734f0",
      "00DRL00000KHFn7=1TBRL0000000K1x",
      "mongodb-site-verification=p6n0w6nnOPjCeuCnsW0Xc4UgAh4jfMHo",
      "",
      "google-site-verification=_BVjdlNMi517YkaWfQ8SOCUxjGyrK4X4tkMeCqieedQ",
      "00Df40000004A8x=1TBVX00000001Tx",
      "00D830000008aVT=1TBcr00000000zJ",
      "cursor-domain-verification-5h3fn5=uPEBnPX0FRt8elKd8xtpotTsg",
      "bcd9860a-1369-4d5c-ae5e-e9320d79f083",
      "00D3k000000ub4r=1TBQQ00000001ov",
      "atlassian-domain-verification=ZOexs0awZv94sBIlIBoxjhW8lXHZ24atEWqaXZtHXJyUNyrJRFD2TUyajwtz1pL1",
      "google-site-verification=33gwj8vJs6_J5adGCJ3IWWAm5C4MeM-ZUy5uzNIEX4s",
      "00Do0000000L7IX=1TBV40000000G8I",
      "00D8A0000005uU8=1TBWA0000004VV3",
      "00Dbf000005BKtN=1TBbf0000000HDm",
      "slack-domain-verification=1Cz4MCZJuypQf1rh9T3qlqJDFCRYuqZkrOUh5kL4",
      "00Ddi000004mJ65=1TBdi0000000FK1",
      "cloudhealth=1659ead7-5c47-4817-a0d3-94b456169734",
      "00DU0000000YT3c=1TBVz00000001CD",
      "uber-domain-verification=233c950b-1660-447a-a8bc-a0bb20559c05",
      "00D7h000000HD25=1TBWL00000005Az",
      "00D3F0000000Nmr=1TBRu0000000dEH",
      "00D1I000003pf77=1TBVv00000000ZV",
      "00D040000000QYW=1TBDc0000008OLs",
      "00DC00000016oM2=1TBcw00000001wz",
      "apple-domain-verification=OAQrNBk5trF8X7H3",
      "00D7j0000004Xkw=1TBdh00000006VF",
      "00D2i0000000pFZ=1TBdh000000079Z",
      "fastly-domain-delegation-RIA8ruNVQ8qqxgwlPyD3-485843-2022-27-04",
      "00D15000000EnBl=1TB7y00000000uT",
      "00D2E000001FGQm=1TBcx000000015l",
      "09/10/2024",
      "perplexity-ai-domain-verification-r24pxy=rliweb0yORQ8UxAD7URTfKgdu",
      "docker-verification=ce0bc02e-16dd-47c2-bb3e-7f6d680dcd47",
      "onetrust-domain-verification=da03b7174c53436587dd407887778160",
      "00D2f0000008gWP=1TBgP00000003kH",
      "Dynatrace-site-verification=e1eb3fe5-f14a-4a0c-b8b6-1c5f380cb804__dfadqbk4o2ngu8n8bho3kom0t",
      "00D8C0000008hms=1TBDZ0000000022",
      "autodesk-domain-verification=EKQ8nv86UxiJDM9bI18R",
      "00D36000000rSuA=1TBPe00000002zV",
      "atlassian-domain-verification=qHOhH89J6Mh62tAEcDaX6swdU8wX1iJZUUlaDWdfkcma0KJ1qVgrfNrxbtBvAOqH",
      "anthropic-domain-verification-ygt3tf=Q9RHyPSxi5ES3lSyMrb5aJ3WV",
      "v=spf1 include:_spf.intel.com -all",
      "00D52000000L89a=1TBVa00000000Uf",
      "canva-site-verification=Udnsc-EibCkG6QIOjQ53WQ",
      "00DQL00000NjvOH=1TBQL0000000pCD",
      "00D23000000Fw7O=1TBWH0000000I6b",
      "00D8c000006KOns=1TBWQ000000023R",
      "00D2D000000E9ZK=1TBWA0000004VGX",
      "00D4B0000009zrY=1TBdh00000007JF",
      "Dynatrace-site-verification=03bc0e9d-4899-45bc-8fb6-963829cd5cf1__m1rmdc12bet67grogkur4kat1r",
      "teamviewer-sso-verification=c0fca594575d4ae58cb4d02d7ede2b3e",
      "e94b687f1bd60e6d49bee301361913c22b1aaf63beb963f10826f8472fced7f1",
      "00Dg0000006V1T1=1TBdh0000000CMA",
      "00D780000004Z0C=1TBVZ0000000M5N",
      "00DE0000000Hxbi=1TBPY00000002OP",
      "08428d8e-d6dd-4d4f-acca-42955adb18cf",
      "00DHu000002tYyb=1TBcv00000004lB",
      "meltwater_sso_20240930",
      "00Ddy000003k0uX=1TBdy00000009cn",
      "00Dco000004OBXu=1TBco00000000BJ",
      "00DcV000002z2LV=1TBcV00000005XZ",
      "atlassian-domain-verification=dfPURS8tP5ncA5xHnEv8nyfRQZzwLH6RRKWNXRHLwny6EBpmC7pwMz1xFLmi/EWH",
      "MS=B03F616C5688CE657CC2FA94EF4E72109431092B",
      "00DWJ000008Mljd=1TBWJ0000000Di1",
      "google-site-verification=tCdhchtzK9L-sDZA5OazdRCeK5HrqgOJ9kZkzdbtmd8",
      "google-site-verification=HZCQBwMXW2bQcmIUCMcxovy1yMxkEcu1mGA2spyLARo",
      "00DO4000007MxTd=1TBO40000000KA2",
      "google-site-verification=pv06NhezCJEfqLpFMO8YKqC6Ye1q85TiFq_S5qUUdxE",
      "00DU0000000JvXT=1TBPb00000000cj",
      "f076027a-8022-4cd7-9c52-373ef56f9848",
      "00DBZ0000008j8l=1TBcn00000001Yn",
      "",
      "docusign=46a68707-4a57-4782-bf77-1373777e73e8",
      "google-site-verification=pIbeNdxnfMeMUhiz7Ad6UlkU08jIlagr9h55GoQSw6I",
      "00DVB0000075KEz=1TBVB00000009Un",
      "atlassian-domain-verification=ApWZ5iliIwA1g0Ka7JhMa7BP0qBkz/WIaMoGiJqvekBz2LJlc2QD7foiLd2h72Rv",
      "google-site-verification=xQ71LIpBIRMAhe6YyAjaNEeqOHF6VOCCLJD-xBsnwtU",
      "onetrust-domain-verification=09f55ff1baba439b9174d37afefcaf2d",
      "00DDn000003r4Pl=1TBQQ000000021p",
      "00Dj0000001tZRR=1TBa6000000012X",
      "onetrust-domain-verification=ee0aec8e25a047c185d8fff907e052c2",
      "bluebeam-verification=ocvjzp7gd8fvt0qv85zgh1og5o3nl9",
      "00D1I000000nTd4=1TBQQ000000017N",
      "openai-domain-verification=dv-lOXezFecTzWt8rrZT7dTGVFq",
      "docusign=ff4d259b-5b2b-4dc7-84e5-34dc2c13e83e",
      "00D2i0000008d6j=1TBTH00000006IL",
      "00DcV000002xNXJ=1TBcV00000000BJ",
      "qqmail-site-verification=de1a8d707315b7e0442efe7a2812e10457a771ccdeb",
      "ms-domain-verification=63e408c2-11b8-4d5f-939c-d71b7d7e3d91",
      "I+FotdhF45rEb5bSOZyqcRNYMIuqDOEcWLtvZ8cb5RKf4p2v+6laazMU1bT8dq88ia98W9aUKYirlD7+tv0Z/A==",
      "00Do0000000aRcf=1TBcv000000029t",
      "00D6w0000004cRG=1TBVA0000000QTx",
      "00Dgy0000000YzN=1TBgy00000000WH",
      "00D36000000K1su=1TBQQ00000001qX",
      "00D5C000000NdC1=1TBce00000001H3",
      "chariot=chariot+intel@praetorian.com",
      "00DKQ0000000ni0=1TBKQ000000KykT",
      "00DDS000001gRdW=1TBOu0000000A2b",
      "00DDD000001fKur=1TBdh000000091h"
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
    "days_left": 68,
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
  "elapsed_s": 90.4,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
