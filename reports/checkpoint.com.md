# Security Audit Report — checkpoint.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://checkpoint.com/ |
| Bug bounty program | Check Point |
| Listed scope domain | checkpoint.com |
| Test date | 2026-09-26 18:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 1, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |
| 7 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 8 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 9 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 7. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 8. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 9. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: mongodb-site-verification=pvGkUyWZIju45KC37L9ajoz48bPvsKlk; google-site-verification=cr-Qr8qr0FvJM7rcCIBbqlvDMj9NGS52rcUPnoRgqjs; mongodb-site-verification=M5kWX33qBcLiAvIAgz5hkUrhSCHQKD6d
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of checkpoint.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 18.65.14.57 carries PTR server-18-65-14-57.hkg61.r.cloudfront.net. for checkpoint.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "checkpoint.com",
  "dns": {
    "a": [
      "18.65.14.57",
      "18.65.14.97",
      "18.65.14.107",
      "18.65.14.81"
    ],
    "aaaa": [
      "2600:9000:20af:200:13:1d23:bc80:93a1",
      "2600:9000:20af:9600:13:1d23:bc80:93a1",
      "2600:9000:20af:9200:13:1d23:bc80:93a1",
      "2600:9000:20af:400:13:1d23:bc80:93a1",
      "2600:9000:20af:7800:13:1d23:bc80:93a1",
      "2600:9000:20af:aa00:13:1d23:bc80:93a1",
      "2600:9000:20af:600:13:1d23:bc80:93a1",
      "2600:9000:20af:7e00:13:1d23:bc80:93a1"
    ],
    "cname": null,
    "mx": [
      "checkpoint-com.mail.protection.outlook.com (pref 100)",
      "checkpoint-com.d-v1.mx.microsoft (pref 0)"
    ],
    "ns": [
      "dns1.p01.nsone.net.",
      "dns3.p01.nsone.net.",
      "dns2.p01.nsone.net.",
      "dns4.p01.nsone.net."
    ],
    "spf": [
      "mongodb-site-verification=pvGkUyWZIju45KC37L9ajoz48bPvsKlk",
      "google-site-verification=cr-Qr8qr0FvJM7rcCIBbqlvDMj9NGS52rcUPnoRgqjs",
      "bd1cea06-a5bf-4bfd-a039-9a725419cf23",
      "mongodb-site-verification=M5kWX33qBcLiAvIAgz5hkUrhSCHQKD6d",
      "google-site-verificationgoogle-site-verification=sTWXCIRPR57b1uy4_mUdDXOP     UAh5Ux7VaeD_XxRGs6Y",
      "miro-verification=7c0ac4c40ca9435f0aac9f3103bad0d29608edce",
      "notion-domain-verification=MnDzXcU9YC9Hhql6uYfvOry2PyxdOlDCsGGta3Ur7ZO",
      "google-site-verification=dwMGbISN9laSvidELOpgLRccCPcbGc5WMQIcFdo_3Ps",
      "hcp-domain-verification=ce2770782fd69f681cffd900bfed1c6c093efb55aaf6e00a7e5e44e0ee7d3576",
      "dropbox-domain-verification=ao680b3a3a15",
      "9rjr8ghmqvjiulmjg4pj423qnt",
      "5452fc6c472e4ce1bfb45f7f0ca753d4",
      "google-site-verification=XG4zgx5SK5nmDbaphm5tc2OTZOOQW9LWzJwOUfdqcIs",
      "720a0827-8d9a-40ca-a879-549d40649674",
      "convex-domain-verification-kvhc58=nGfltUnhvMinm9kxR67cPMQAC",
      "google-site-verification=rFuYxjFBb219O8AIjD8joMkMWhtZPanxPJS-6s6lN3w",
      "apple-domain-verification=7QhtdqjdDG2t0PMa",
      "box-domain-verification=8527ca495818001dfe42380446cd6b5d63d282aed94758a8228116acafc3d961",
      "8a2f84e6-93c4-45cf-9759-8e724f1aa616",
      "twilio-domain-verification=3d65c3ee9c1bacb1c92a6f4aa4254168",
      "mongodb-site-verification=sKKFmlh0taqfo3eE3BoCDkOkO6uSw507",
      "lyIRWpl30ICYZA1WEdosDihosuS0m3ahty0WpjuUcIoVImkL60t5Kor5QyQowt29jmi8JBmQF+0AYPnbpMOUnA==",
      "deb3128a-b74b-4b27-95a8-82b4fcf7a1c5",
      "1password-site-verification=2CR4T6ZCSJHYRFCDCGML7PCK2E",
      "2fd959111ffb4474b7e02863e00ac28a",
      "36988e76-f426-444a-bf29-0f7d16d2a1a8",
      "airtable-verification=61d226de8d29fd1aee7eae9064ef1c40",
      "fbd29d20-3129-4d07-aff9-0b67547c8bdf",
      "cloudflare_dashboard_sso=7880b55133859ba9fa37cd64c26c7649",
      "1895fd12-6155-44d9-8cf1-d034ed3f9081",
      "mixpanel-domain-verify=1ed58526-836b-41ed-91df-b19d63df84f1",
      "34CDDF42E93DC8291A9FFB03F2782CB4406FE5842A2FC9E75760DC7CE8988EFA",
      "docusign=9500ab24-ae00-4143-934c-5ad0edbea319",
      "mongodb-site-verification=wvXvntDeK8AqOHC8TzmXnr5voFTkaq6S",
      "slack-domain-verification=hBJ7iTCUxDdnWYUKNBHmsz7tlpoCPKDxLBrGLs0R",
      "2a2676f6-e6fc-4754-ab3e-04e7808724e7",
      "jcpsie6ji2tbgufb8m4mh1s0pi",
      "mongodb-site-verification=aCsGW9rrjprkpiRFqzJ8lnd9AooUUBNg",
      "mongodb-site-verification=EquOvFierKYIw7qYM8ec3pFiayGjsr6r",
      "70fdee12-bf32-4950-92bc-91a3632bd3f6",
      "hvtq0fjm2jxf9j7kr459rm3g30dc3svl",
      "google-site-verification=vYWPDJt28gEcEjzGCiN18Rnb-udh_2qF1puEbWPp8wI",
      "45d45d4e-f35c-4473-9360-68660dbf576d",
      "j0r31jspuaai48ae3d7rab3k4e",
      "c980eab4-f13e-4564-b6b2-8861251b065e",
      "770b9561-17b7-420e-a00c-59f674664b5e",
      "aws-securityagent-domain-verification=OXtfIcQPcY-5NwX74v_8wA",
      "MS=ms61202101",
      "fc8c2548-22f2-4582-8b9b-457f358d5aef",
      "ikxg6gkc7y0k6ugegi08qa0ycc",
      "slack-domain-verification=2Vp6FzIgIx71fuWYtdQfSKvw6a6RaN4YHFPWufEr",
      "cursor-domain-verification-13a8v3=ug0qsYud0fpm2BJSguDtZQfID",
      "MS=ms48383339",
      "monday-com-verification=V8qtBgdqStqxSyGsvuVwdjz3csBZs2A3ZdEPwJ9G3Qg",
      "mongodb-site-verification=F3c1IhUI81YAogWYmRzAOXTdCHxwE0OY",
      "docker-verification=e197713e-0cdd-4b07-9db9-3dfe2037c9d9",
      "cisco-ci-domain-verification=7789c9b6b84bd5a5c267020a5a320674e95dd78eba75b34a10e15563164c5882",
      "4ee983f9-5422-4889-a5ba-1df355c2973b",
      "ivtccuvjt7kv0cnop38g5gn1ob",
      "hubspot-domain-verification=OTI1ZWQ5N2UtMWVjZS00MTk5LTliNTEtNWNkNTNiNTlhZmIw",
      "v=spf1 include:_spf1.b1723vyl.eu.cp-dmarc.com ~all",
      "notion-domain-verification=ElTTtPkiVIyV0H8Mwklw6KKczIH6eHyEhyecdZ07VXz",
      "mgverify=1c587286111c349875a099c382eb88c9ab1fe5dfcc3487506d9b49839ba117ab",
      "jqh0Jx01f2FL5Ktxt+ugQQ3RS3PWtK0kXxapIgEb/9I+/r0fTaeE7oXzMQUAED9ifJ/156eRCnddwrwbjIE5QQ==",
      "facebook-domain-verification=r4djys91aknh85fhkxmz3z5t48gt4q",
      "7b4c4c32-2a80-48d7-ab91-dfd4cf41dfe4",
      "notion_verify_]-KBzH-e+aa7ja2_MeLin9#*@McMu5rP44_*,]yU?50i~.nuQ8twrcmR=F0A8.2CCsp>s~",
      "status-page-domain-verification=2h0hq9z9ztj5",
      "canva-site-verification=ucSy6Km-oyeB5kmmd7ozmg",
      "MS=ms22023784",
      "f28a3f6e-1959-4a86-a3e4-46a3b5974c17",
      "37d894f4-2dab-4879-b69a-12cae50ccfc4",
      "jR=TrQdaY5lxw4bR0=NDW9TrJSzVdu-9u4xaFPuF5EZV",
      "2d7209d5-35fe-487a-becb-2ff9e6d21c4d",
      "atlassian-domain-verification=OAFLhunIHAsvjL1SCeeNaYiPslEf7JXjseLgxMXSyiKvzuqI/y3v/mfQHaFoC9uY",
      "google-site-verification=vPb8jQJ2tMku_eJtjkdiri8EIiepr76S2543L_mgqO0",
      "c793c6d9-34df-4485-bdb9-efced2aa5fb9",
      "mongodb-site-verification=enRLfN4wAWgImh6gWNEWUlB4EiHZyDHb",
      "q5upo64pn9dfl0u34h2a1bkk1f"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;sp=none;rua=mailto:cpall@eu.cp-dmarc.com,mailto:dmarcreports@checkpoint.com;ruf=mailto:cpall@eu.cp-dmarc.com,mailto:dmarcreports@checkpoint.com;fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.checkpoint.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign GCC R3 DV TLS CA 2020",
    "notBefore": "Jun 17 06:44:08 2026 GMT",
    "notAfter": "Jan  2 06:44:08 2027 GMT",
    "san": [
      "*.checkpoint.com",
      "checkpoint.com"
    ],
    "days_left": 97,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "18.65.14.57",
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
      "origin": "https://sub.checkpoint.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://checkpoint.com/"
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
    "/.well-known/security.txt": 202,
    "/security.txt": 202,
    "/.git/HEAD": 202,
    "/.git/config": 202,
    "/.env": 202,
    "/.htaccess": 202,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 202,
    "/server-status": 202,
    "/api/": 202
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "mongodb-site-verification=pvGkUyWZIju45KC37L9ajoz48bPvsKlk",
    "google-site-verification=cr-Qr8qr0FvJM7rcCIBbqlvDMj9NGS52rcUPnoRgqjs",
    "mongodb-site-verification=M5kWX33qBcLiAvIAgz5hkUrhSCHQKD6d",
    "google-site-verificationgoogle-site-verification=sTWXCIRPR57b1uy4_mUdDXOP     UA",
    "miro-verification=7c0ac4c40ca9435f0aac9f3103bad0d29608edce"
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
      "aia_ocsp": null,
      "not_before": "20260617064408",
      "not_after": "20270102064408"
    }
  },
  "x12": {
    "status": 202,
    "ptr": [
      "server-18-65-14-57.hkg61.r.cloudfront.net."
    ]
  },
  "elapsed_s": 11.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
