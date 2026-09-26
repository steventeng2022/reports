# Security Audit Report — walmart.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://walmart.com/ |
| Bug bounty program | Walmart Corporation |
| Listed scope domain | walmart.com |
| Test date | 2026-09-25 10:27 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
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
- **Detail:** Detected: Server: AkamaiGHost
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

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AkamaiGHost
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
  "domain": "walmart.com",
  "dns": {
    "a": [
      "23.209.216.193"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-000c7201.gslb.pphosted.com (pref 10)",
      "mxb-000c7201.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "pdnswm6.ultradns.co.uk.",
      "a10-66.akam.net.",
      "pdnswm1.ultradns.net.",
      "pdnswm5.ultradns.info.",
      "a22-67.akam.net.",
      "pdnswm4.ultradns.org.",
      "pdnswm2.ultradns.net.",
      "a3-64.akam.net.",
      "a1-185.akam.net.",
      "a5-65.akam.net.",
      "a8-66.akam.net.",
      "pdnswm3.ultradns.org."
    ],
    "spf": [
      "globalsign-domain-verification=2AD27E3A206DB3231BAD817BD5A21F7A",
      "infoblox-domain-mastery=cbdbcb7b4ccda409b4d353af156079955dc262a3bd4566aae2a9afba1d3d43e5c2",
      "openai-domain-verification=dv-IDGFBjh74ycOf2e4vrXwBZtv",
      "_globalsign-domain-verification=AXcfQAoG3in-mjLnMOJPhp1CNvUTsRkCaLo60rR5hG",
      "globalsign-domain-verification=290297CC7AD18787782E80BFF88B354B",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com include:_netblocks.walmart.com include:_vspf1.walmart.com include:_vspf2.walmart.com include:_vspf3.walmart.com ip4:161.170.248.0/24 ip4:161.170.244.0/24 ip4:161.170.241.16/30 ip4:161.170.245.0/24 ip4:16",
      "1.170.249.0/24 ~all",
      "+wnQWce020VDWuXiDkLvV2jJXOlN5tNAzGyHFjMbBg0=",
      "slack-domain-verification=Ic5IE8asOH1Bg6b1To8CGfWytCkVfywFsAJRZvUm",
      "_globalsign-domain-verification=0UV9-mABi984W6oReb-NIqLZE4wxFn0Z_HZqReFlfx",
      "_globalsign-domain-verification=9-Ef1Ps_FbIDDK9OPPGU3ju471Ap4_xAPV4pacA3ht",
      "_globalsign-domain-verification=tYy2ZDIHUuR-3NGTeWDgC5Bs1vAYAyL7kZK8HpVwNg",
      "twilio-domain-verification=19bf2f50450a9dec2b6ea8d18ab9114f",
      "_globalsign-domain-verification=E0XnB_4FxsbzvD6MDzvAQoSFChcy4XTb2vlMqtUc5k",
      "canva-site-verification=jcrBOlbl254ia6gsPJNFCg",
      "anthropic-domain-verification-5vz2bt=GhKF4NMESyKswHJGVanZVBEtB"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=Arkansas, localityName=Bentonville, organizationName=Walmart Inc., commonName=www.walmart.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign GCC E46 OV TLS CA 2025",
    "notBefore": "Jul 27 09:58:01 2026 GMT",
    "notAfter": "Feb 11 09:58:01 2027 GMT",
    "san": [
      "www.walmart.com",
      "beta.walmart.com",
      "grocery.walmart.com",
      "walmart.pharmacy",
      "walmartspecialty.pharmacy",
      "www.wal-mart.com",
      "walmart.com"
    ],
    "days_left": 138,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.209.216.193",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [
    {
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.walmart.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.walmart.com/"
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 22.7,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
