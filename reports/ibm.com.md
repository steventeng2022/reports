# Security Audit Report — ibm.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ibm.com/ |
| Bug bounty program | IBM |
| Listed scope domain | ibm.com |
| Test date | 2026-09-27 01:23 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 6, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 19 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 20 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 21 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 20 days (notAfter Oct 17 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=3600 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.ibm.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: onetrust-domain-verification=e7e09cedfb9b4ff386f1274e4c214d55; Dynatrace-site-verification=76b6b299-fe43-4f31-889b-a8a467193478__8q74sg9dg5udjp; google-gws-recovery-domain-verification=48225137
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but ibm.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 154 disallow path(s), e.g. /account/registration, /account/mypro, /account/myint, /Admin, /cgi-
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://ibm.com/ carries Cache-Control: max-age=0; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 19. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 184.84.207.120 carries PTR a184-84-207-120.deploy.static.akamaitechnologies.com. for ibm.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 20. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for ibm.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 21. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on ibm.com identify the edge as Akamai; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

## Evidence (raw response observations)

```json
{
  "domain": "ibm.com",
  "dns": {
    "a": [
      "184.84.207.120"
    ],
    "aaaa": [
      "2600:140b:1c00:1b8d::3831",
      "2600:140b:1c00:1b83::3831"
    ],
    "cname": null,
    "mx": [
      "mx0a-001b2d05.pphosted.com (pref 5)",
      "mx0b-001b2d05.pphosted.com (pref 5)"
    ],
    "ns": [
      "dns4.p05.nsone.net.",
      "dns3.p05.nsone.net.",
      "dns1.p05.nsone.net.",
      "dns2.p05.nsone.net."
    ],
    "caa": [],
    "spf": [
      "onetrust-domain-verification=e7e09cedfb9b4ff386f1274e4c214d55",
      "Dynatrace-site-verification=76b6b299-fe43-4f31-889b-a8a467193478__8q74sg9dg5udjppn95utrb8bct",
      "00d50000000c9mweay",
      "google-gws-recovery-domain-verification=48225137",
      "mongodb-site-verification=Gcqpap80hVonXfV2VnYC6AlEr2Z9vvf3",
      "google-site-verification=aH5jG_abrxRKeKZKOrX9CuXlXdFSCQxVkmAVoYwzNcc",
      "wework-site-verification=hhWLSbG4qiaKhsXU",
      "atlassian-domain-verification=WAjTH82C5Zx475WLKAA2nrdlsoA/kN0ej9igrLrED4h15KMHPOm+A5H3GndKAxDC",
      "intersight=1439768961d2f6d736c38b947d235947681cd817abea13eab3daee9ecbdc6c3d",
      "smartsheet-site-validation=I-lI3gCPdvKbKQ6KTki96Ream6Yjs1gU",
      "mongodb-site-verification=gEevYaKFpagtLmrYxomtpE2QmYwnd29i",
      "intersight=cfe6f48b59e7428442b9aab04765ca0953e01c480a685ca5cf6939ef9e505532",
      "00D10000000biEb=1TBQ80000000b2n",
      "google-site-verification=ewe2QcP5aMj3DKuSfxscZME5wip4EpoTxCXPNvr0-J0",
      "google-site-verification=I-empodMpM7n5Px1doUgIaOKHKeIMXXf6k8Ea5ENyO4",
      "smartsheet-site-validation=TaCpXPZ-qFfOgfHXuMrfF8_d6GZjICNl",
      "apple-domain-verification=M3o953J0rN1B0P2a",
      "figma-domain-verification=b8b3862b529816383e0e7ec9ad2757f8f7b4a0f4da290136796f1aa36d558841-1785230801",
      "google-gws-recovery-domain-verification=42135076",
      "MS=ms61389031",
      "coursera-domain-verification=To0Ej5CrewXrC0FcCjVxXG1lTcLLJQjvrW2gdUt8rCxFxTGMdA0vA54nUlgLfbyO",
      "facebook-domain-verification=7w4exj2revwpv5u708s6bji5j6tswy",
      "figma-domain-verification=6db9259c4472f3e5ba44c7ae284b4f4b8aa0268c0797659a5e1a28ccfe912ddf-1741206863",
      "h1-domain-verification=m9jGKLYa5hDdU5AHUfK9jrBmWVhx3h9t9ztfDFMaxZfgChvk",
      "anthropic-domain-verification-ym2t7s=RPDdVAMpzgbooX0kxhqstuM2D",
      "DomainVerification=CYICZMSWT62KDTQWZ1YCKKU763NN36BQJ4TD5BV606K3FLDUR3UOJE58E30FTIVL",
      "asv=e8bb80eeac60e62a4dd07f03d1d36829",
      "docker-verification=7c4d4e40-e7ee-4183-94c2-db97d0873269",
      "atlassian-domain-verification=a32Aj0uoXQRh6QseDFFrlufYlkbeSdok7az3sY0DQNVXpW1Iqj8zlsuXFZgHMojH",
      "ms-domain-verification=1adbc779-89ce-47cf-8167-c4e4a3b4a6aa",
      "amazonses:79ShwQazteb+WkCt8e297sAC2mwZVRditsrzaoxiHjU=",
      "atlassian-sending-domain-verification=79afa9af-6e0f-47e6-b636-2786f8772f66",
      "ms-domain-verification=bedcd06e-7e1c-4906-9b6a-b4a1095fa4ed",
      "google-site-verification=tzdngH5fWH-k8uQoDVovOFJQZTwaGtDOP6S2cQlOvCs",
      "jamf-site-verification=CN4bHigc1ZnD6ZQX_2c6XQ",
      "adobe-idp-site-verification=5f8adca7-512f-44e1-a5b2-b62c5e3763f2",
      "00df40000004784eaa",
      "_analyst_ng_validation=f6702989-83f3-42b8-be39-19cf8f1c33f5",
      "40a21f5affe343c6b37e0a5af80dcd93",
      "00d00000000hedieay",
      "yandex-verification: 5f458b477256c50c",
      "00D3h000004YkeYEAS",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all",
      "_github-challenge-ibm.ibm.com=2613e984bc",
      "mongodb-site-verification=3d0wR0KvanH3yTbll0sXEJ0QGBQffOkv",
      "docker-verification=846278f4-7e2c-4586-ae26-e1a9f0f0aecd",
      "atlassian-domain-verification=79ZnqmRPyDwm6b99GAF3ymzBmjtRZU9oCfgMwVMAUGlrPPenDc6esgO62jafAXUI",
      "google-site-verification=Jck8mLbYYfCnrmi_nRy4MG2fbUN3UGhC29KdspGLd9Y"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=none; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=Armonk, organizationName=International Business Machines Corporation, commonName=ibm.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Oct 17 00:00:00 2025 GMT",
    "notAfter": "Oct 17 23:59:59 2026 GMT",
    "san": [
      "ibm.com",
      "asmarterplanet.com",
      "blog.turbonomic.com",
      "bluewolf.com",
      "heal.ibm.com",
      "heal.ibm.org",
      "ibm.org",
      "ibm.ua",
      "ibm100.com",
      "ibmbigdatahub.com",
      "lendyr.com",
      "maas360.com",
      "sevone.com",
      "turbonomic.com",
      "www.asmarterplanet.com",
      "www.bluewolf.com",
      "www.ibm.com",
      "www.ibm.ua",
      "www.ibm100.com",
      "www.ibmbigdatahub.com",
      "www.lendyr.com",
      "www.maas360.com",
      "www.sevone.com",
      "www.turbonomic.com"
    ],
    "days_left": 20,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "184.84.207.120",
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
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.ibm.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ibm.com/"
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
    "onetrust-domain-verification=e7e09cedfb9b4ff386f1274e4c214d55",
    "Dynatrace-site-verification=76b6b299-fe43-4f31-889b-a8a467193478__8q74sg9dg5udjp",
    "google-gws-recovery-domain-verification=48225137",
    "mongodb-site-verification=Gcqpap80hVonXfV2VnYC6AlEr2Z9vvf3",
    "google-site-verification=aH5jG_abrxRKeKZKOrX9CuXlXdFSCQxVkmAVoYwzNcc"
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
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 13152435256831142421648033345563166620,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
        "http://crl4.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl"
      ],
      "subject_dn": "310b30090603550406130255533111300f060355040813084e657720596f726b310f300d0603550407130641726d6f6e6b31343032060355040a132b496e7465726e6174696f6e616c20427573696e657373204d616368696e657320436f72706f726174696f6e3110300e0603550403130769626d2e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473320544c532045434320534841333834203230323020434131",
      "not_before": "20251017000000",
      "not_after": "20261017235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/account/registration",
      "/account/mypro",
      "/account/myint",
      "/Admin",
      "/cgi-",
      "/contact/employees/servlets",
      "/data/",
      "/db2s",
      "/developerworks/*-pdf.pdf$",
      "/developerworks/forums/servlet",
      "/developerworks/forums/abuse",
      "/developerworks/forums/post",
      "/docs/api",
      "/fcgi-",
      "/fscripts"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a184-84-207-120.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.ibm.com/",
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
    "hsts": "max-age=3600",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "cdn": [
      "Akamai"
    ]
  },
  "elapsed_s": 11.8,
  "rechecked": "2026-09-27 01:08 UTC"
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
- Findings are reported against the public program scope; submission through the program tracker is pending.
