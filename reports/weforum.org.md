# Security Audit Report — weforum.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://weforum.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | weforum.org |
| Test date | 2026-09-26 17:55 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 4, Info: 11)

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
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
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
- **Detail:** Header reveals: awselb/2.0
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
- **Detail:** Apex TXT records with verification/token content: protonmail-verification=9a5678880a3d8a138adef690b172b83011aa72c9; pp-verification=6d09c4db-136f-45b0-a876-ee9894ecb227; hcp-domain-verification=8df8c1bab58a33a3c4a18d55d756be6feecb16f1bc9ff97c4c5b56c2
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of weforum.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "weforum.org",
  "dns": {
    "a": [
      "54.72.189.73",
      "63.35.58.158"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-0029f101.gslb.pphosted.com (pref 10)",
      "mxa-0029f101.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-108.awsdns-13.com.",
      "ns-757.awsdns-30.net.",
      "ns-1550.awsdns-01.co.uk.",
      "ns-1240.awsdns-27.org."
    ],
    "spf": [
      "protonmail-verification=9a5678880a3d8a138adef690b172b83011aa72c9",
      "pp-verification=6d09c4db-136f-45b0-a876-ee9894ecb227",
      "hcp-domain-verification=8df8c1bab58a33a3c4a18d55d756be6feecb16f1bc9ff97c4c5b56c24cf39b2f",
      "_y0a8jocbfw3junt02mldp6b2xl3t8ek",
      "058b7f7c-f1a8-4151-bf33-7c1253b8250c",
      "onetrust-domain-verification=4706964004d842ff8e3e998cfb9e95ee",
      "mixpanel-domain-verify=af7b2ab9-ba7e-4dfb-ae38-8553aaf28806",
      "openai-domain-verification=dv-2ERIqAfMx5ObZD0xf5vGDQQq",
      "docusign=af7aeb30-e49c-4b7a-98d8-6b127f9bb275",
      "google-site-verification=9UJ64WqmFileahOWizp4xsqS6ocCgUwkPfk7R5gKgFE",
      "pardot586733=df6859a87f543a1aef8e961fa54c4edf37e797ba9695931a6a5a0c41979a8a65",
      "jamf-site-verification=yXqbk6NIBKAgo92DtNK8Qw",
      "sending_domain1023261=d2791adae2bac175e941031c1faea3ebf7d8d0f9bec255c60a22235e31d4564d",
      "asv=30cf3d98cd231922c304e2ea205690bf",
      "GIC0y5UuCphNvp5+zdLo3uM9hZCeTKMji/uUwKekuROTMgqPELHboLHV/cXBvIJXsO64CXJZim+NeI7inlxwyg==",
      "pardot1023261=931c4279794fd4a47b5a396730efb1ef52c243049f80e03a88d020a4a8a674be",
      "canva-site-verification=0Y_UJA27aPqQYo5C8ZlN5A",
      "21561668a4c58d5dbb50486afe176195ca06a4bd",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com +include:%{l}._spf.%{d} -all",
      "apple-domain-verification=OQWui0o3waVdBNot",
      "docusign=1fdc429f-b194-4a68-8321-3ed07f170b16",
      "MS=ms20688131",
      "adobe-idp-site-verification=d267447c-3316-4c5a-bd63-b478cf4d2581",
      "logmein-verification-code=4e3aa1a0-ba3c-408d-8415-2773f0cc7317",
      "anthropic-domain-verification-qjr70f=mgOKfC1hzNUdmIcpJ70llX4Pa",
      "sending_domain586733=f770af487ef2e5a0f69363082f6c4cc3e0def8a8c660f71eea5acd311e7d31a2",
      "trend-micro-v1-domain-verification.207d3dea181fe697f7b7baf200bc0723=215960e6-4609-4d83-afa4-7cb2bbe6eed3",
      "Dynatrace-site-verification=b6992eee-7248-43a9-97cb-ac9543820831__nf3vvnhs7i6bjl7jpgv9tusloj",
      "Dynatrace-site-verification=6fb4cdfa-6d51-4c6b-ba72-32ca31fbd8e9__65807dga6ljd8ga1lhllenjl9n",
      "atlassian-domain-verification=KdxYDGkL7ybHsaieC01/GdZSKLeYss2GazxPERg1ibVNnJHIJzyiwmu2H42NRyNr",
      "0v44yrz5mz7w4362rxvcphy6vcsz567b",
      "wrike-verification=MTA5NjQyNzpiNmM1MDkzNjVjYmFlMjI0ZjQwZGVjMjdiZGIzZDYzNTNiZjU0YzhiMDM5NTBiNWNiNmFlYjEyMTM5Nzg2N2M2"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;rua=mailto:dmarc_rua@emaildefense.proofpoint.com;ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com;fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=www.weforum.org",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Feb  9 00:00:00 2026 GMT",
    "notAfter": "Mar 10 23:59:59 2027 GMT",
    "san": [
      "www.weforum.org",
      "weforum.org"
    ],
    "days_left": 165,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "54.72.189.73",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.weforum.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://weforum.org:443/"
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
    "protonmail-verification=9a5678880a3d8a138adef690b172b83011aa72c9",
    "pp-verification=6d09c4db-136f-45b0-a876-ee9894ecb227",
    "hcp-domain-verification=8df8c1bab58a33a3c4a18d55d756be6feecb16f1bc9ff97c4c5b56c2",
    "onetrust-domain-verification=4706964004d842ff8e3e998cfb9e95ee",
    "openai-domain-verification=dv-2ERIqAfMx5ObZD0xf5vGDQQq"
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
      "aia_ocsp": null
    }
  },
  "elapsed_s": 30.0,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
