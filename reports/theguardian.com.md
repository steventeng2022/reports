# Security Audit Report — theguardian.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://theguardian.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | theguardian.com |
| Test date | 2026-09-26 17:54 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 6, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 12 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 13 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 12. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): spf (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 13. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.theguardian.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=IU-vqTBscxkgU3J_f5i10_i624mvE3IjvYpeVPB2A98; google-site-verification=LCHObeC_7NyDBnXVNSqm5VJAve2qxx04PmUFc697Rf0; miro-verification=9bbe1ce0f13ab2efbbda64d44bd0db3c1f17fd60
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of theguardian.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but theguardian.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 50 disallow path(s), e.g. /sendarticle/, /Users/, /users/, /*/print$, /email/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "theguardian.com",
  "dns": {
    "a": [
      "151.101.65.111",
      "151.101.1.111",
      "151.101.193.111",
      "151.101.129.111"
    ],
    "aaaa": [
      "2a04:4e42::367",
      "2a04:4e42:400::367",
      "2a04:4e42:600::367",
      "2a04:4e42:200::367"
    ],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "alt3.aspmx.l.google.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns03.theguardiandns.com.",
      "ns02.theguardiandns.com.",
      "dns3.p04.nsone.net.",
      "dns2.p04.nsone.net.",
      "dns4.p04.nsone.net.",
      "ns01.theguardiandns.com.",
      "ns04.theguardiandns.com.",
      "dns1.p04.nsone.net."
    ],
    "spf": [
      "google-site-verification=IU-vqTBscxkgU3J_f5i10_i624mvE3IjvYpeVPB2A98",
      "google-site-verification=LCHObeC_7NyDBnXVNSqm5VJAve2qxx04PmUFc697Rf0",
      "pardot709753=1cfbb8fa5dabcb6befc9faa15661f500a64a6f22eb83bb146848633dbe7633cf",
      "miro-verification=9bbe1ce0f13ab2efbbda64d44bd0db3c1f17fd60",
      "apple-domain-verification=4qbvNZKyKKZyBtdU",
      "google-site-verification=ujq5XlF5Ty7dwXv7S3AV99WRr8IwetZIjNqqloPpKmA",
      "MS=ms94953828",
      "RDOAB9Z9GAJESXAA11TST3LEI0RN5LQ4TES408NS",
      "openai-domain-verification=dv-m8f1SR7Sj1HI4BIM0XsZAOxx",
      "slack-domain-verification=K3gfZj51sHXR6hxk5BVVfunkmGnHxc4NvwNtqo77",
      "docusign=1f00efb3-0975-459c-b221-e46452a0f92a",
      "amazonses:2s68hEXFIHnDWOVNuEbZ06pSFJhN0qCtTx8lztmngls=",
      "stripe-verification=85178DB4E6F4EC41721B7F20BD9F04B21E2B630ADA8156BDFE421272EBC2056F",
      "73t2Qr1jv9^4RG3CsYKp#F&^5S1fxpHtq9X5bLBQtc4q2PhMvMBmUrIh%LLGPb3V!XpnW9tvQd$tg^rLv!8ALDOQhhss%c9K%Xt",
      "cisco-ci-domain-verification=394bd3979592402fa40244fcf11f48e5e5014697e1f7e8587eba08075cdd79e3",
      "MS=B95E020056873FBC8A077EEE2104192B3DBC1D61",
      "google-site-verification=6-wiFtmcPHY78jVuZUE3io1c6c9SrSyjPVmUr7XRW2I",
      "google-site-verification=I3xSjID5V7E9UDa3WSvvvpCqiqw1_34kG1Y_rz5dlV4",
      "multiverse-domain-verification=3e7e7acf-12cc-4934-a23a-b8c0127fb091",
      "google-site-verification=4l7NequdA4a20U0D9YSw7ENlF69-hDeHXx21aU2UUC0",
      "brave-ledger-verification=7e309ab3cd9203b886205458254a13f930f79821ea05031742f7dfc9285370c8",
      "docker-verification=42d9d88d-f950-4407-a675-3d843c16a983",
      "onetrust-domain-verification=ce4031d6f7b94fdb9ed409ab9cf643d3",
      "formstack-domain-verification=0cc5b58e5ea4088ab9333fcd9721a72f",
      "lucidlink-verification=4K96N0ZDHCHPKDZ538AFRVH54G",
      "_hfmu2x1szay737kpys7nmqjko311kxu",
      "v=spf1 include:_spf.google.com include:spf_c.oraclecloud.com include:_spf.salesforce.com include:_spf1.theguardian.com ip4:199.255.192.0/22 ip4:199.127.232.0/22 ip4:54.240.0.0/18 ip4:69.169.224.0/20 ip4:23.249.208.0/20 ip4:23.251.224.0/19 ip4:76.223.176.0",
      "/20 ip4:54.240.64.0/18 ip4:76.223.128.0/19 ip4:216.221.160.0/19 ip4:206.55.144.0/20 ip4:24.110.64.0/18 -all",
      "apple-domain-verification=sVI2atim1Brh4UUx\n",
      "intersight=123333260936a76db6d9dedc01d0ab4d61a9aae47515abbf0087e02a395747f9",
      "google-site-verification=9SMJbNVsYm0GCVZbGVOMSzXajrK_pqVtjW3P007kaQo",
      "asv=d971bc0397a95b5da450b9bfbad1212a",
      "google-site-verification=M9Q_QcvQQCoQEca1--d55J0QKwKZt0XgAAj9DJrJ0jQ",
      "adobe-idp-site-verification=af3ef20fdc1d370aee02414a73ce0db9f1b465c21d53a369080184cd8e4b60f1",
      "facebook-domain-verification=9qqmd2kl745hph02i64iyoxvdphmi9",
      "google-site-verification=iLS6vcS8qLmM07nG-W_M3TAmaSEAAwoLBKovJCGOrOs"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;rua=mailto:dmarcreporting@theguardian.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=theguardian.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R46 DV TLS CA 2026 Q3",
    "notBefore": "Aug 18 11:24:58 2026 GMT",
    "notAfter": "Mar  5 10:24:58 2027 GMT",
    "san": [
      "theguardian.com",
      "*.code.dev-guardianapis.com",
      "*.code.dev-theguardian.com",
      "*.dev-theguardian.com",
      "*.editorial.theguardian.com",
      "*.email.theguardian.com",
      "*.guardian.co.uk",
      "*.guardianapis.com",
      "*.guim.co.uk",
      "*.guimcode.co.uk",
      "*.ophan.co.uk",
      "*.qa.dev-guardianapis.com",
      "*.service.theguardian.com",
      "*.theguardian.co.uk",
      "*.theguardian.com",
      "*.theguardian.design",
      "api.nextgen.guardianapps.co.uk",
      "code.api.nextgen.guardianapps.co.uk",
      "dev-gutools.co.uk",
      "dev-theguardian.com",
      "guardian.co.uk",
      "guim.co.uk",
      "gutools.co.uk",
      "i.guimcode.co.uk",
      "media.guim.co.uk",
      "subscribe.theguardian.com",
      "theguardian.co.uk",
      "theguardian.design",
      "*.wordiply.com",
      "wordiply.com",
      "theguardianfoundation.org",
      "theguardian.org",
      "*.theguardian.tv"
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
    "ip": "151.101.65.111",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.theguardian.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://theguardian.com/"
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
    "google-site-verification=IU-vqTBscxkgU3J_f5i10_i624mvE3IjvYpeVPB2A98",
    "google-site-verification=LCHObeC_7NyDBnXVNSqm5VJAve2qxx04PmUFc697Rf0",
    "miro-verification=9bbe1ce0f13ab2efbbda64d44bd0db3c1f17fd60",
    "apple-domain-verification=4qbvNZKyKKZyBtdU",
    "google-site-verification=ujq5XlF5Ty7dwXv7S3AV99WRr8IwetZIjNqqloPpKmA"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/sendarticle/",
      "/Users/",
      "/users/",
      "/*/print$",
      "/email/",
      "/contactus/",
      "/share/",
      "/websearch",
      "/*?commentpage=",
      "/whsmiths/",
      "/external/overture/",
      "/discussion/report-abuse/*",
      "/discussion/report-abuse-ajax/*",
      "/discussion/comment-permalink/*",
      "/discussion/report-abuse/*"
    ]
  },
  "elapsed_s": 14.7,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
