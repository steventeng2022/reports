# Security Audit Report — washingtonpost.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://washingtonpost.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | washingtonpost.com |
| Test date | 2026-09-27 02:48 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 4, Info: 17)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
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
| 15 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 18 | info | H25 | server-timing response header exposed | CWE-200 |
| 19 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 20 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 21 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 8 days (notAfter Oct  5 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: AkamaiGHost
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=0R8HaEZPmx7XZBckUaQMssOU2e6Dspe3AOMsYxNrWq8; _globalsign-domain-verification=SQONiBgTxRVzPPtIHjei_IUGCiAa0KxoVWFw1QfVes; google-site-verification=6Bi3yUCN2g3lzvqapLfrbgkQxob5YCjmZidGa2qiM4g
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://washingtonpost.com/ carries Cache-Control: max-age=0; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.77.20.196 carries PTR a23-77-20-196.deploy.static.akamaitechnologies.com. for washingtonpost.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkccd1y8b0ga05.html -> 403; error page/headers match: Akamai.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 18. [INFO] server-timing response header exposed (`H25`)

- **CWE:** CWE-200
- **Detail:** The root response of washingtonpost.com sends server-timing (cdn-cache; desc=HIT, edge; dur=1, ak_p; desc="1790477309338_388906780_409747012_); server/edge processing metrics are disclosed to any client.
- **Recommendation:** Restrict server-timing to authenticated/debug contexts if the internals are sensitive.

### 19. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on washingtonpost.com identify the edge as Akamai; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 20. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of washingtonpost.com is http://ocsp.sectigo.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 21. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of washingtonpost.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

## Evidence (raw response observations)

```json
{
  "domain": "washingtonpost.com",
  "dns": {
    "a": [
      "23.77.20.196"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-001a3c01.gslb.pphosted.com (pref 10)",
      "mxa-001a3c01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-1027.awsdns-00.org.",
      "ns-404.awsdns-50.com.",
      "ns-666.awsdns-19.net.",
      "sdns34.ultradns.net.",
      "sdns34.ultradns.org.",
      "sdns34.ultradns.com.",
      "sdns34.ultradns.biz.",
      "ns-1840.awsdns-38.co.uk."
    ],
    "caa": [
      "0 issue \"amazonaws.com\"",
      "0 issue \"amazontrust.com\"",
      "0 issue \"pki.goog\"",
      "0 issue \"awstrust.com\"",
      "0 issue \"entrust.net\"",
      "0 issue \"amazon.com\""
    ],
    "spf": [
      "_40ij1ve2dtneubti00ikilfe0zlr0kz",
      "google-site-verification=0R8HaEZPmx7XZBckUaQMssOU2e6Dspe3AOMsYxNrWq8",
      "_globalsign-domain-verification=SQONiBgTxRVzPPtIHjei_IUGCiAa0KxoVWFw1QfVes",
      "google-site-verification=6Bi3yUCN2g3lzvqapLfrbgkQxob5YCjmZidGa2qiM4g",
      "google-site-verification=Xq6gcVYYZJtb2DQN6h2bo-hkrdmZpcdAKO8CeYl8290",
      "f3de1c77b72748ff92a68f88f4d93dfd",
      "slack-domain-verification=YsnaUOhPU4Y6dCz5a3TqBIs4DxEXrVFbuKbGFRyS",
      "google-site-verification=qcYuOKvxobypPYmqzzrcw5KiwtpfLgdEEt-HwMfLwvo",
      "v=spf1 ip4:198.72.14.0/23 ip4:192.72.255.0/24 ip4:54.156.98.51 ip4:54.210.51.17 include:spf.protection.outlook.com include:madgexjb.com include:spf-001a3c01.pphosted.com include:amazonses.com -all",
      "brave-ledger-verification=28c1597498b6eafc29aac1f3a42f31559dfe03a832058ead6f684a518f180d62",
      "MS=ms58521745",
      "knowbe4-site-verification=e04590e121eee5fbc18ada6449219119",
      "_rm8r4wsr378iet73p2f9j7oecnksay1",
      "_zj8o0fyk0qj8jy5pt1zr1543e97ew7c",
      "rovag_verification_token=C2158E1BE1D041B78CC57ED72101FF6C",
      "_globalsign-domain-verification=R1bvWDvJUF1gpXlmc7Q3deFwpZciil5dpJR4t-a8XM",
      "google-site-verification=xLI97dy4D9FGihhl23twW5HHhVSmpnr2nWComZhpQVo",
      "mBd2513ESDgG6ZfaSrFYw4WaOC2b0M21Ehl8KWI3GmgTDpfYKwGuBum8ivsayoYLzVCetyXDieRUdW4qdQe+hw==",
      "globalsign-domain-verification=8frsHcE2ag-0ccaaP5BTpPmUJC8ob8pdjDQchfAWzD",
      "_dhwsbe1t7yht6p4dsc72mcajq9aaum9"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; fo=1; rua=mailto:dmarc_rua@washingtonpost.com,mailto:mylza-8368@rua.dmarc.emailanalyst.com; ruf=mailto:dmarc_ruf@washingtonpost.com,mailto:mylza-8368@ruf.dmarc.emailanalyst.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=District of Columbia, organizationName=WP Company LLC, commonName=www.washingtonpost.com",
    "issuer": "countryName=CA, organizationName=Entrust Limited, commonName=Entrust OV TLS Issuing ECC CA 2",
    "notBefore": "Sep  5 00:00:00 2025 GMT",
    "notAfter": "Oct  5 23:59:59 2026 GMT",
    "san": [
      "www.washingtonpost.com",
      "apps.washingtonpost.com",
      "css.washingtonpost.com",
      "img.washingtonpost.com",
      "img2.washingtonpost.com",
      "img3.washingtonpost.com",
      "js.washingtonpost.com",
      "live.washingtonpost.com",
      "subscribe.washingtonpost.com",
      "washingtonpost.com"
    ],
    "days_left": 8,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.77.20.196",
    "open": []
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.washingtonpost.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 403
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 403,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 403,
    "/security.txt": 403,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=0R8HaEZPmx7XZBckUaQMssOU2e6Dspe3AOMsYxNrWq8",
    "_globalsign-domain-verification=SQONiBgTxRVzPPtIHjei_IUGCiAa0KxoVWFw1QfVes",
    "google-site-verification=6Bi3yUCN2g3lzvqapLfrbgkQxob5YCjmZidGa2qiM4g",
    "google-site-verification=Xq6gcVYYZJtb2DQN6h2bo-hkrdmZpcdAKO8CeYl8290",
    "slack-domain-verification=YsnaUOhPU4Y6dCz5a3TqBIs4DxEXrVFbuKbGFRyS"
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
      "aia_ocsp": "http://ocsp.sectigo.com",
      "serial": 129569819040921427503474861084474632770,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.sectigo.com/EntrustOVTLSIssuingECCCA2.crl"
      ],
      "san": [
        "www.washingtonpost.com",
        "apps.washingtonpost.com",
        "css.washingtonpost.com",
        "img.washingtonpost.com",
        "img2.washingtonpost.com",
        "img3.washingtonpost.com",
        "js.washingtonpost.com",
        "live.washingtonpost.com",
        "subscribe.washingtonpost.com",
        "washingtonpost.com"
      ],
      "subject_dn": "310b3009060355040613025553311d301b060355040813144469737472696374206f6620436f6c756d62696131173015060355040a130e575020436f6d70616e79204c4c43311f301d060355040313167777772e77617368696e67746f6e706f73742e636f6d",
      "issuer_dn": "310b300906035504061302434131183016060355040a130f456e7472757374204c696d69746564312830260603550403131f456e7472757374204f5620544c532049737375696e67204543432043412032",
      "not_before": "20250905000000",
      "not_after": "20261005235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 403,
    "ptr": [
      "a23-77-20-196.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 403,
    "http_status": 403,
    "p404_status": 403,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 403,
    "crl": {
      "url": "http://crl.sectigo.com/EntrustOVTLSIssuingECCCA2.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 403
  },
  "x16": {
    "root_status": 403,
    "server_timing": "cdn-cache; desc=HIT, edge; dur=1, ak_p; desc=\"1790477309338_388906780_409747012_16_6319_38_30_-\";dur=1",
    "cdn": [
      "Akamai"
    ]
  },
  "x17": {
    "ocsp_http": "http://ocsp.sectigo.com"
  },
  "elapsed_s": 9.7,
  "rechecked": "2026-09-27 02:16 UTC"
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
- re-run #17 passive additions: the retired-header angles (Public-Key-Pins, Expect-CT, X-Permitted-Cross-Domain-Policies, Via, COOP/COEP, Permissions-Policy) read from the one root GET; the wildcard SAN, http:// OCSP and 398-day-cap angles use the certificate evidence the base TLS check already captured (SAN now harvested from the existing DER); the only extra requests this pass are three read-only GETs (/.well-known/dpop-jwks.json, /.well-known/origin-rsa-keys.json, /.well-known/llms.txt).
- Findings are reported against the public program scope; submission through the program tracker is pending.
