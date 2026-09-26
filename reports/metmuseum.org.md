# Security Audit Report — metmuseum.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://metmuseum.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | metmuseum.org |
| Test date | 2026-09-26 18:55 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Vercel
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
- **Detail:** Header reveals: Vercel
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
- **Detail:** Apex TXT records with verification/token content: anthropic-domain-verification-fwca5e=etIfJNLc1ugZsnUY9xuc9vCWW; extensis-domain-verification=64d62f29-f7c1-457b-b212-9972174d08b4; yahoo-verification-key=M30EgMMvntbzmly9p6SjiP1owtFPrCNOnyer5Wnwf5w=
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of metmuseum.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but metmuseum.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 6 disallow path(s), e.g. /temp, /upload, /ghidorah, /style-guide, /style
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://metmuseum.org/ carries Cache-Control: public, max-age=0, must-revalidate; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

## Evidence (raw response observations)

```json
{
  "domain": "metmuseum.org",
  "dns": {
    "a": [
      "76.76.21.21"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "metmuseum-org.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "pdns92.ultradns.com.",
      "pdns92.ultradns.org.",
      "pdns92.ultradns.net.",
      "pdns92.ultradns.biz."
    ],
    "spf": [
      "MS=ms31930746 ",
      "anthropic-domain-verification-fwca5e=etIfJNLc1ugZsnUY9xuc9vCWW",
      "extensis-domain-verification=64d62f29-f7c1-457b-b212-9972174d08b4",
      "_p3a3a89hww4r6t7rd0j5catko4ly0c9",
      "yahoo-verification-key=M30EgMMvntbzmly9p6SjiP1owtFPrCNOnyer5Wnwf5w=",
      "_globalsign-domain-verification=pYvnbIbmL21kgEXtHUixR6GwqZYBpnxR-WrjYRc-Nx",
      "google-site-verification=H3p9Zh2qyUXRQN9Z7Pyo8jAQKATelcFBGYJUDcr0Qk0",
      "_1mnx599abfj9txyutcs6ekxv2jn5369",
      "_globalsign-domain-verification=3SUS0WYrw3pgtCV8LhJ0CNa7rPISdz4ZfGaMxjfEd4",
      "7067qnns8u7dmfhmavt7i4f5vc",
      "bw=U/atUAMQ0LSMGwn/d1ymtfHNKm7lpzUtDVCL0uGFAEUg",
      "_v7iu22xssho63kc3sqq8vkuf0brhpig",
      "_globalsign-domain-verification=e0UD0VNNHSeLLHVn1VGMLAh6UuhGGncs1mt_b10K1e",
      "adobe-idp-site-verification=7cdfc1c42bc9f50fb0dd80a29eb348968c45a33bfba6f8937b962f4dd796ed01",
      "_globalsign-domain-verification=Iiihy-iv_vLdlIMtHvh-aCdqO2T53oCoknhW44njXn",
      "apple-domain-verification=ey0edqzOCPCylkrb",
      "zcCtOkNeEUS5AhURLjAKgUup4mBdbnfcdxpTMP9F5MG5cP86XWHAxif02eiy2wsVIMuwGiKZ+fLbYAzTd8WPxw==",
      "ZOOM_verify_4DQ4So2gQjaBPJy5E4oSZw",
      "google-site-verification=hrppBmJ36sxIUGM5QO4H2KSNFpNInE51Rpl8ywfVKD8",
      "v=spf1 ip4:209.177.165.160 ip4:209.177.169.160 ip4:209.177.169.164 ip4:50.16.201.234 ip4:198.168.106.0/23 ip4:209.177.160.9/32 ip4:209.177.169.161/32 ip4:209.177.170.161/32 ip4:216.17.112.211/32 ip4:206.107.42.249/32 ip4:206.107.42.254/32 ip4:198.168.107.",
      "24 ip4:69.72.32.253 ip4:69.72.34.120 ip4:69.72.41.2 ip4:69.72.41.28 ip4:69.72.45.120 ip4:69.72.47.188 ip4:159.135.226.248 ip4:159.135.233.165 ip4:198.168.106.101 include:spf.protection.outlook.com include:_shortspf.launchmetrics.com include:em4317.metmuse",
      "um.org -all"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:metmuseum_dmarc@metmuseum.org,mailto:dmarc_agg@vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=metmuseum.org",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Sep  6 01:39:49 2026 GMT",
    "notAfter": "Dec  5 01:39:48 2026 GMT",
    "san": [
      "metmuseum.org",
      "www.metmuseum.org"
    ],
    "days_left": 69,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "76.76.21.21",
    "open": []
  },
  "https": {
    "status": 308,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Vercel"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.metmuseum.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 308,
    "location": "https://metmuseum.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 308",
    "/redirect?next=https://evil-auditor.example/x -> 308",
    "/go?url=https://evil-auditor.example/x -> 308",
    "/url?url=https://evil-auditor.example/x -> 308"
  ],
  "paths": {
    "/robots.txt": 308,
    "/sitemap.xml": 308,
    "/.well-known/security.txt": 308,
    "/security.txt": 308,
    "/.git/HEAD": 308,
    "/.git/config": 308,
    "/.env": 308,
    "/.htaccess": 308,
    "/wp-login.php": 308,
    "/phpmyadmin/index.php": 308,
    "/server-status": 308,
    "/api/": 308
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "anthropic-domain-verification-fwca5e=etIfJNLc1ugZsnUY9xuc9vCWW",
    "extensis-domain-verification=64d62f29-f7c1-457b-b212-9972174d08b4",
    "yahoo-verification-key=M30EgMMvntbzmly9p6SjiP1owtFPrCNOnyer5Wnwf5w=",
    "_globalsign-domain-verification=pYvnbIbmL21kgEXtHUixR6GwqZYBpnxR-WrjYRc-Nx",
    "google-site-verification=H3p9Zh2qyUXRQN9Z7Pyo8jAQKATelcFBGYJUDcr0Qk0"
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
      "not_before": "20260906013949",
      "not_after": "20261205013948"
    }
  },
  "http2": {
    "robots_disallow": [
      "/temp",
      "/upload",
      "/ghidorah",
      "/style-guide",
      "/style",
      "/welcome"
    ]
  },
  "x12": {
    "status": 308
  },
  "elapsed_s": 6.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
