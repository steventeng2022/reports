# Security Audit Report — uber.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://uber.com/ |
| Bug bounty program | Uber |
| Listed scope domain | uber.com |
| Test date | 2026-09-25 10:24 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 1, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ufe
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ufe
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "uber.com",
  "dns": {
    "a": [
      "69.48.216.17"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 2)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "edns126.ultradns.org.",
      "edns126.ultradns.com.",
      "edns126.ultradns.net.",
      "edns126.ultradns.biz."
    ],
    "spf": [
      "c9s6q2+D+iTzxyax7z2ol/gbj0Rqq8Loojleaq22ZDM=",
      "tiktok-developers-site-verification=cCZKENHfoFc48Ks8x4K7IMa9NCyD1ggk",
      "ca3-ffffa27c6ab6493ba5e2ffd4f8961467",
      "google-site-verification=9kwu-dlf_JSf0XtaHK2xK-Cowpra8TnHbfTRCa7NBk0",
      "hpe-greenlake-domain-verification=6553304837784b7232736d71514737737353622d6854354e343534554c71754f",
      "google-site-verification=p21addAHCLTiBqVhN6P3leSJNO2ob8edJtQbICdXCj8",
      "apple-domain-verification=NGLGgklojeSRTo9T",
      "autodesk-domain-verification=wa1khlrPnOY-93pE5_nH",
      "dtm-domain-verification=EtPupN9aHsJIAtWeUzmu_aAa6o5BQsvO73iDfQIKkx4",
      "google-site-verification=yHvJ7x6qUkjrzRfaPzSO5Iu42eP70uSS0Q88xPFBbSU",
      "SFMC-4eGhjXSll4RESL8vyX0CBVbTfffzejZShsyAXBrT",
      "apple-domain-verification=Da2R4Md5eAUVUg038WJnE-_ifFtCwYYc_Dlmx3EaPsU",
      "mandrill_verify.UYz1FLL51N9Ky3RCgCUZGQ",
      "crz6wwryflvvfk4kvk5lqfk78p02dc7m",
      "openai-domain-verification=dv-wtb3VIyo0DtnGsiQN4DnZ4c7",
      "workplace-domain-verification=HhUs1CkDiWsL4Nlmkdb6IOVjrebKb1",
      "postman-domain-verification=4c640467e16a94ba218b31f435eb42e0749d16ab4168939f9ad5eb4ec3abb91cd63ca90ef5ccd3e4a8f4049444c3a267225ffde0ea6a9c8d84bb6e904034a1cc",
      "facebook-domain-verification=fgnbsxqefhg2pzugzl4vcw82ylgagg",
      "MS=607A6B094E5395250B2F88D76D42FFB6DC2C18A4",
      "_26a8qlr3df4hbl6zve94e918z0g5wud",
      "uber-site-verification=56157b0f-0f5f-4bdc-8a64-9c313ac173a5",
      "atlassian-sending-domain-verification=0302bdf3-f835-4464-979d-7beeda0dbe97",
      "docusign=ce93a9f0-d430-4abb-aee8-ec66524c1f12",
      "v=spf1 include:uber.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:mailgun.org ~all",
      "atlassian-domain-verification=MMotF76tU47LiNcsEf06+lzKmWly4PgbYpYZqHy3a9YdTdY4S43ay72YkkxTmzff",
      "duo_sso_verification=efpKKW3WtEX7Ln6CBDAQyyNA5mwOU0KxFopDN2LtcawWUcGa6BByYIq5LG69lDrq",
      "mixpanel-domain-verify=a35ee3f7-3848-4a0b-822e-d429b507c0c6",
      "lovable_verification=workspace_01jz0y1v0ff9cv8hsxkbvawqhx",
      "google-site-verification=bywbMPdGdGaSev-nAuHwbdYjZziw9oPeGkOgBD5UyK0",
      "docker-verification=e121526a-c4bd-4829-8f6b-c4a3c93f0029",
      "docusign=635f0402-4f58-42de-8e07-e1da6d8a971a",
      "beautifulai-site-verification=ed0fad99-1b20-4963-ab5b-538f0f915117",
      "Dynatrace-site-verification=95915cac-be11-4e1a-81b7-9580122d59d1__vrv8sf7b41uebre15lgg3c5tko",
      "paloaltonetworks-site-verification=f567a8ba5a35da704fb1e540c1e50bbaa33bc2ea6b87193c22e1c9ae29348b2a",
      "notion-domain-verification=ReKaEX54F5cGF2V3IKgyilPZF3TjQ34Iua63ng0LHDC",
      "stripe-verification=79f7b9921824c7fd1cd4ffc20fc10f662a5322317c8290f124b4e18d9ebd19e0",
      "atlassian-domain-verification=M5S2mTVz1nn58QsIgP0q4BLRplQvKva5IHHG5usoAYecrD00FTI5zR2tzAmNnI9L",
      "omnissa-connect-verification-da151bda-e79c-445f-9099-1fead7f31add",
      "f621e431-a485-4094-8587-2f76f441ccab",
      "duo_sso_verification=EArnP8qJQk9QUv3i30tGmhVOfsuivQxEgBlNLIF8EaD3ZimeyV2Iq5rBJQHWcaUMl",
      "AD5-G1R-7NJ",
      "mandrill_verify.5Qnmy5yihDZ4mJwXJ0VP7w"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Francisco, organizationName=Uber Technologies, Inc., commonName=*.uber.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Feb 15 00:00:00 2026 GMT",
    "notAfter": "Feb 16 23:59:59 2027 GMT",
    "san": [
      "*.uber.com",
      "uber.com"
    ],
    "days_left": 144,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "69.48.216.17",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: ufe"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.uber.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://uber.com:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 429",
    "/url?url=https://evil-auditor.example/x -> 429"
  ],
  "paths": {
    "/robots.txt": 429,
    "/sitemap.xml": 429,
    "/.well-known/security.txt": 429,
    "/security.txt": 429,
    "/.git/HEAD": 429,
    "/.git/config": 429,
    "/.env": 429,
    "/.htaccess": 429,
    "/wp-login.php": 429,
    "/phpmyadmin/index.php": 429,
    "/server-status": 429,
    "/api/": 429
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 27.7,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
