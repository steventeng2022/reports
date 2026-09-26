# Security Audit Report — tripadvisor.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://tripadvisor.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | tripadvisor.com |
| Test date | 2026-09-26 14:56 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 3, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "tripadvisor.com",
  "dns": {
    "a": [
      "65.9.180.77",
      "65.9.180.51",
      "65.9.180.28",
      "65.9.180.34"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 10)"
    ],
    "ns": [
      "ns-1455.awsdns-53.org.",
      "ns-1702.awsdns-20.co.uk.",
      "ns-584.awsdns-09.net.",
      "ns-218.awsdns-27.com."
    ],
    "spf": [
      "segment-site-verification=Lv56Wm7ECxH2FrJtoG9FmQ77Co6nf93L",
      "docker-verification=a6e2315b-2f86-428a-84d7-52270aea1853",
      "cursor-domain-verification-bwta0g=rGWNgTQrx8pQ3A5XE0S1XxKzM",
      "asv=d902c0e169042b928445d5bc9a610e24",
      "atlassian-domain-verification=w2N0fg0r/RRZCQ7UgNfpKKFXJH1kvCtLacvj/HzML7VZYyhEDT7N1skt744NCyxJ",
      "stripe-verification=A71BECF4CEF430F171A6A2382BEECE6A64B9633FC460020EB8A205A95669B679",
      "cisco-ci-domain-verification=6de74e9c24339dc358b099e999ca47c34dd162c04f635f9810372e2000ad9f57",
      "pardot_211512_*=005e7416cb39efdf4ede9f02352c05fe01bf0e6c5435039550bdab7d707cae58",
      "perplexity-ai-domain-verification-2hn78f=hnjr1IgErK6Rjhxpscmyv9Ztq",
      "anthropic-domain-verification-pc5mq6=ebxPo8aNNofNaqlqU65hyJHjA",
      "_2erojipq9p68ygptyqgypy83ah2dnzz",
      "teamviewer-sso-verification=b42c480c302645eb8ed8f32688556be4",
      "facebook-domain-verification=rld5ayte5pgnngj4ljg2ovn3kaeo4q",
      "datadome-domain-verify=LtwSY8f9UsuWkflYriVEN5xJW7jb1OGB",
      "zapier-domain-verification-challenge=e7c8b772-89e7-420e-b76b-3a084b0bbf83",
      "google-site-verification=XMWC5EUo1s-TCtWPBEwzBDLUHqlmf-UcS-t7E8YRlmw",
      "jamf-site-verification=Ac2uXdbieW6reJXv2o4UQw",
      "b4jddSWKFAZrS-Y8QD1o7T2nzdk",
      "spf2.0/pra",
      "MS=ms43904515",
      "_globalsign-domain-verification=GaLfs98jrznUbwIzD2n4S8pINM0PU-EyBVWkTTQvp9",
      "_18y5y646xcsfq732og6fu2xmgabh125",
      "google-site-verification=u10Ue1BCmah8YviQ9Ju9IqSP-xZtlgEnBloxhP5Lhn8",
      "twilio-domain-verification=57fba14b7bba9c1c99652540a081cc79",
      "onetrust-domain-verification=9214adc265ab47e992a332150c6a315b",
      "miro-verification=6ff1de40e337f458d05086183318e55305c99fe1",
      "docusign=4c82afdc-4187-4e03-9e78-8dbdc5ed7d0d",
      "protonmail-verification=5e35a64e327cebe41439dc21e8657f78970c051a",
      "docusign=f4d14366-23f0-482a-bc08-98b15bd25db6",
      "duo_sso_verification=N763Lu3Yt0ygaRnHrvqziKZ7YVtOU95w7GXyHhCljSOT7d1KVi7z2TSRd5BR4a3Q",
      "sprout-social-85a564fb-ff50-11ef-b8c4-0e418c465417",
      "v=spf1 include:_spf.tripadvisor.com include:mail.zendesk.com ~all",
      "bnyGlxykTsBZSdNWWe3jXJ5tVU2U7gsTx6UjsZyIpHk=",
      "apple-domain-verification=jtPwxHyUkw7GVjBd",
      "MS=E0371C101EE1151078A9F24A7375E7021319CF9E",
      "bugcrowd-verification=4889742e219d4b280f2d3673d147a6a9",
      "jetbrains-domain-verification=5zlraawspitiqhi2hp4wizy31",
      "bitrise-verification=b03d9c7c59423f9c-nSSshb2Ef1iv",
      "astro-domain-verification=cmhtl2g8213y801lqzjo38fe8",
      "openai-domain-verification=dv-5I8xhFhqZatLn3rbDbmtgpc2",
      "pendo-domain-verification=M8PpCcCrkPq-ll2Fr1arfZA1YvI"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-rua@tripadvisor.com; ruf=mailto:dmarc-ruf@tripadvisor.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=tripadvisor.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Aug 19 00:00:00 2026 GMT",
    "notAfter": "Mar  4 23:59:59 2027 GMT",
    "san": [
      "tripadvisor.com",
      "tripadvisor.jp",
      "tripadvisor.dk",
      "tripadvisor.com.eg",
      "tripadvisor.fr",
      "tripadvisor.ua",
      "tripadvisor.co.nz",
      "tripadvisor.nl",
      "tripadvisor.com.my",
      "tripadvisor.com.mx",
      "tripadvisor.rs",
      "tripadvisor.com.gr",
      "tripadvisor.de",
      "tripadvisor.pt",
      "tripadvisor.fi",
      "tripadvisor.co.hu",
      "tripadvisor.be",
      "tripadvisor.com.au",
      "tripadvisor.cz",
      "tripadvisor.com.pe",
      "tripadvisor.com.ar",
      "tripadvisor.es",
      "tripadvisor.com.tr",
      "tripadvisor.com.ph",
      "tripadvisor.com.vn",
      "tripadvisor.at",
      "tripadvisor.ch",
      "tripadvisor.in",
      "tripadvisor.co.il",
      "tripadvisor.co.kr",
      "tripadvisor.cl",
      "tripadvisor.com.hk",
      "tripadvisor.com.tw",
      "tripadvisor.co.za",
      "tripadvisor.co",
      "tripadvisor.it",
      "tripadvisor.ca",
      "tripadvisor.sk",
      "tripadvisor.com.sg",
      "tripadvisor.com.br",
      "tripadvisor.ie",
      "tripadvisor.co.uk",
      "tripadvisor.co.id",
      "tripadvisor.se"
    ],
    "days_left": 159,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "65.9.180.77",
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
      "origin": "https://sub.tripadvisor.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://tripadvisor.com/"
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
  "elapsed_s": 27.9,
  "rechecked": "2026-09-26 14:53 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
