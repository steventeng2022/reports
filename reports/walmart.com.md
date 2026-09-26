# Security Audit Report — walmart.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://walmart.com/ |
| Bug bounty program | Walmart Corporation |
| Listed scope domain | walmart.com |
| Test date | 2026-09-26 23:40 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

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
| 10 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | low | H21 | HSTS does not cover subdomains | CWE-319 |

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

### 10. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=AXcfQAoG3in-mjLnMOJPhp1CNvUTsRkCaLo60rR5hG; _globalsign-domain-verification=E0XnB_4FxsbzvD6MDzvAQoSFChcy4XTb2vlMqtUc5k; openai-domain-verification=dv-IDGFBjh74ycOf2e4vrXwBZtv
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but walmart.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 57 disallow path(s), e.g. /0/, /55875582/walmart-us/catalog/, /account/, /api/, /collection/api/logger
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.209.216.193 carries PTR a23-209-216-193.deploy.static.akamaitechnologies.com. for walmart.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on walmart.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of walmart.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

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
      "pdnswm4.ultradns.org.",
      "a3-64.akam.net.",
      "pdnswm1.ultradns.net.",
      "a1-185.akam.net.",
      "pdnswm6.ultradns.co.uk.",
      "a8-66.akam.net.",
      "pdnswm5.ultradns.info.",
      "a10-66.akam.net.",
      "a22-67.akam.net.",
      "pdnswm2.ultradns.net.",
      "a5-65.akam.net.",
      "pdnswm3.ultradns.org."
    ],
    "caa": [
      "0 issue \"digicert.com\"",
      "0 issue \"globalsign.com\"",
      "0 issue \"amazon.com\""
    ],
    "spf": [
      "_globalsign-domain-verification=AXcfQAoG3in-mjLnMOJPhp1CNvUTsRkCaLo60rR5hG",
      "_globalsign-domain-verification=E0XnB_4FxsbzvD6MDzvAQoSFChcy4XTb2vlMqtUc5k",
      "openai-domain-verification=dv-IDGFBjh74ycOf2e4vrXwBZtv",
      "canva-site-verification=jcrBOlbl254ia6gsPJNFCg",
      "_globalsign-domain-verification=tYy2ZDIHUuR-3NGTeWDgC5Bs1vAYAyL7kZK8HpVwNg",
      "anthropic-domain-verification-5vz2bt=GhKF4NMESyKswHJGVanZVBEtB",
      "slack-domain-verification=Ic5IE8asOH1Bg6b1To8CGfWytCkVfywFsAJRZvUm",
      "_globalsign-domain-verification=0UV9-mABi984W6oReb-NIqLZE4wxFn0Z_HZqReFlfx",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com include:_netblocks.walmart.com include:_vspf1.walmart.com include:_vspf2.walmart.com include:_vspf3.walmart.com ip4:161.170.248.0/24 ip4:161.170.244.0/24 ip4:161.170.241.16/30 ip4:161.170.245.0/24 ip4:16",
      "1.170.249.0/24 ~all",
      "+wnQWce020VDWuXiDkLvV2jJXOlN5tNAzGyHFjMbBg0=",
      "infoblox-domain-mastery=cbdbcb7b4ccda409b4d353af156079955dc262a3bd4566aae2a9afba1d3d43e5c2",
      "globalsign-domain-verification=2AD27E3A206DB3231BAD817BD5A21F7A",
      "globalsign-domain-verification=290297CC7AD18787782E80BFF88B354B",
      "_globalsign-domain-verification=9-Ef1Ps_FbIDDK9OPPGU3ju471Ap4_xAPV4pacA3ht",
      "twilio-domain-verification=19bf2f50450a9dec2b6ea8d18ab9114f"
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
    "days_left": 137,
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "_globalsign-domain-verification=AXcfQAoG3in-mjLnMOJPhp1CNvUTsRkCaLo60rR5hG",
    "_globalsign-domain-verification=E0XnB_4FxsbzvD6MDzvAQoSFChcy4XTb2vlMqtUc5k",
    "openai-domain-verification=dv-IDGFBjh74ycOf2e4vrXwBZtv",
    "canva-site-verification=jcrBOlbl254ia6gsPJNFCg",
    "_globalsign-domain-verification=tYy2ZDIHUuR-3NGTeWDgC5Bs1vAYAyL7kZK8HpVwNg"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": "http://ocsp.globalsign.com/gsgcce46ovtlsca2025",
      "serial": 27121310723762650179181494782,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.globalsign.com/gsgcce46ovtlsca2025.crl"
      ],
      "subject_dn": "310b30090603550406130255533111300f0603550408130841726b616e736173311430120603550407130b42656e746f6e76696c6c6531153013060355040a130c57616c6d61727420496e632e311830160603550403130f7777772e77616c6d6172742e636f6d",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312a302806035504031321476c6f62616c5369676e2047434320453436204f5620544c532043412032303235",
      "not_before": "20260727095801",
      "not_after": "20270211095801"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/0/",
      "/55875582/walmart-us/catalog/",
      "/account/",
      "/api/",
      "/collection/api/logger",
      "/cp/-201",
      "/cp/-302",
      "/cp/-306",
      "/cp/-309",
      "/cp/-506",
      "/cp/-509",
      "/cp/api/logger",
      "/cp/api/wpa",
      "/cservice/",
      "/cservice/ya_index.gsp"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a23-209-216-193.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.walmart.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=31536000",
    "crl": {
      "url": "http://crl.globalsign.com/gsgcce46ovtlsca2025.crl",
      "status": 200
    }
  },
  "elapsed_s": 8.8,
  "rechecked": "2026-09-26 23:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- Findings are reported against the public program scope; submission through the program tracker is pending.
