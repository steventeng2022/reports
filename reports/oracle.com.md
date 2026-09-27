# Security Audit Report — oracle.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://oracle.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | oracle.com |
| Test date | 2026-09-27 01:29 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 5, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 15 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 16 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): spf, spf, spf, spf (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

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
- **Detail:** Apex TXT records with verification/token content: webexdomainverification.=d729667e-36b8-4d4a-bbb7-0f3069025573; webexdomainverification.JRJC=6ac35490-0c1a-4729-b3fc-78a568159417; webexdomainverification.=a3652afd-f531-4076-9a45-1e184df3a2d6
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 138.1.33.162 carries PTR ocomtld-prod.appoci.oracle.com. for oracle.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 15. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The oracle.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 16. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to oracle.com negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

## Evidence (raw response observations)

```json
{
  "domain": "oracle.com",
  "dns": {
    "a": [
      "138.1.33.162"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-00069f01.gslb.pphosted.com (pref 20)",
      "mxa-00069f01.gslb.pphosted.com (pref 20)"
    ],
    "ns": [
      "a1-160.akam.net.",
      "ns2.p201.dns.oraclecloud.net.",
      "a18-67.akam.net.",
      "ns4.p201.dns.oraclecloud.net.",
      "a13-65.akam.net.",
      "ns3.p201.dns.oraclecloud.net.",
      "ns1.p201.dns.oraclecloud.net.",
      "a11-66.akam.net."
    ],
    "caa": [
      "0 issue \"pki.goog\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"digicert.com\""
    ],
    "spf": [
      "webexdomainverification.=d729667e-36b8-4d4a-bbb7-0f3069025573",
      "webexdomainverification.JRJC=6ac35490-0c1a-4729-b3fc-78a568159417",
      "webexdomainverification.=a3652afd-f531-4076-9a45-1e184df3a2d6",
      "amazonses:w4vl+NQAMony+agN9mt8H5MV4isrTCU3iFGSFSmgs7E=",
      "webexdomainverification.F00R=81ccb499-274a-447d-a54a-934bb0dafec4",
      "webexdomainverification.=1f146848-946a-45a1-b021-4b3d4ef924d6",
      "ciscocidomainverification=1864e14e0478e40197a9f4b07e52f6add508db236b82a10b6aa2df2eac6fe75b",
      "atlassian-domain-verification=1Oromr6nviNhRSPQouu6eUUWlzUzqZt/84xNgWEunEkHEvAK1oY0i9GaHlO7MPi4",
      "MS=ms68450787",
      "webexdomainverification.=6d066ca0-8f37-48c6-8a96-1909343f9c23",
      "amazonses:bGS07pWw+FmfvUu4KgJNzF1GIZqr8BJrrqcw7NtMJlI=",
      "atlassian-domain-verification=dKssjBiaoCdxRMWHZE/bBDYu4Wh4oJ6P6tJ/jxDKM37grHev0Qa5eWhnuAi1lJfJ",
      "webexdomainverification.=603d007e-3304-48a2-b9bc-c8d22b669304",
      "adobe-idp-site-verification=897d22d1-bca0-4449-90a4-1ac86c506dcd",
      "paloaltonetworks-site-verification=8759980204930d68307e4387f6b7db958dec60048cc1053aa8f0a7396916c491",
      "docusign=061e3d77-6c9b-4908-afd2-b2f02c39ecf2",
      "webexdomainverification.LSOE=4e1c3c86-abf0-4902-8a84-b34420ef075c",
      "webexdomainverification.LSOJ=4b3a4ca8-7b0a-4bbc-8816-686e1bb4ddf7",
      "webexdomainverification.=5c0fd5af-2fff-48d7-a138-10711dd460bb",
      "webexdomainverification.JRGF=35895e43-87ca-4bdf-8feb-b7a0e22694f3",
      "anthropic-domain-verification-f69hf4=EP3M2VJ8RvglBNY3ipKf1ChUb",
      "atlassian-domain-verification=xpCgyo81RlS8Nywge8zAU0pqo89fXgqXNsCp9VVSIxP2j0Z9sthcjZbygEUlocRy",
      "webexdomainverification.=cfeaa219-cb2c-458e-baea-d24703ba2355",
      " _4tbszkg4ufy8su1xuke2bq2zfmzx3mm",
      "MS=ms56590334",
      "zoom-domain-verification = 31c4caad-f2b3-4ef8-8d92-26df2e836f3e",
      "cloudhealth=647661d7-af1e-4696-88b6-eed192d10e56",
      "webexdomainverification.=2f927290-1d5f-4df2-b1bb-bbb71bea85a9",
      "google-site-verification=wXL-gAW01OVDMhb-6YPCh4XxwPBIXfGhGDcQhLSzd-k",
      "webexdomainverification.=bbd0294a-bc53-46f4-b21c-8dfab1cb7666",
      "amazonses:WiyIwuGeeSNOIz7rqmlfP1MfDGCQFLMv4MgUsvcUTWE=",
      "5mqsjfm8mpy57x4xwfs8dbfrgx14vhs5",
      "yandex-verification: 4f894a8e737184e9",
      "webexdomainverification.JIOB=3bc19d00-8f37-45bd-9799-e8ffa9c77306",
      "webexdomainverification.HO6U=eeb397a4-2b0c-4475-ae07-56dfc4507757",
      "webexdomainverification.=21e2aa9c-745f-4388-a31f-eac4f6c16444",
      "v=spf1 include:spf_s.oracle.com include:spf_r.oracle.com include:spf_c.oraclecloud.com include:spf_x.oracle.com include:spf_z.oracle.com include:stspg-customer.com ~all",
      "docusign=2be17354-8326-4a61-8700-8276a284f7f8",
      "webexdomainverification.=e86664eb-38ad-46f7-aa1a-60203dfca9a0",
      "google-site-verification=Tpoo3Bhw4cI4JjPp4v2RZz3JzSNkYg98yPwOLanQ2gI",
      "google-site-verification=RzPlMxOfod0eiMchm-MP3BhdhPgDHzL2mE_mAD91IWg",
      "zoom-domain-verification",
      "=",
      "31c4caad-f2b3-4ef8-8d92-26df2e836f3e",
      "webexdomainverification.JM3I=c1caad11-9eb5-4c76-877d-06dcfcb95db3",
      "amazonses:rJLKgYvappkvPl76X7w/Eeq6Qdk9AorogfUGE0NB0G8=",
      "webexdomainverification.=d3071182-7ce2-4cb6-b315-90e9b7f866dc",
      "webexdomainverification.=04ce0c34-7d39-41dd-a3ba-627a30cd205c",
      "google-site-verification=IwkBNLXsgiyZ9wUuXa1-PynELZFJlYOduHp7uPcTfdo"
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
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Redwood City, organizationName=Oracle Corporation, commonName=oracle.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jun  4 00:00:00 2026 GMT",
    "notAfter": "Dec 19 23:59:59 2026 GMT",
    "san": [
      "oracle.com",
      "oracleimg.com",
      "oraclecloud.com",
      "www.oraclecloud.com",
      "opower.com",
      "blog.opower.com",
      "powerup.opower.com",
      "support.opower.com",
      "www.opower.com",
      "conject.com",
      "support.conject.com",
      "www.conject.com",
      "push.io",
      "www.push.io",
      "bigmachines.com",
      "crowdtwist.com",
      "aconex.com",
      "blog.aconex.com",
      "www.aconex.com",
      "selectminds.com",
      "ocomtld-stage.appoci.oracle.com",
      "ocomtld-prod.appoci.oracle.com",
      "ocomtld-dr.appoci.oracle.com",
      "stage.mysql.com",
      "mysql.com",
      "mysql.se",
      "mysql.fi",
      "mysql.lu",
      "mysql.biz",
      "mysql.info",
      "mysql.org",
      "mysqlnetwork.us",
      "mysqlnetwork.com",
      "mysqlnetwork.org",
      "mysqlnetwork.biz",
      "mysqlab.com",
      "mysqlcorp.com",
      "mysqlserver.net",
      "mysqlpress.com",
      "mysqlpress.org",
      "mysqlpress.biz",
      "mysqlpress.net",
      "mysql-press.biz",
      "mysqlpress.us",
      "sakila.net",
      "sakila.org",
      "sakila.biz",
      "sakila.us",
      "innodb.com",
      "planetmysql.net",
      "planetmysql.info",
      "planetmysql.biz",
      "planetmysql.org",
      "sun.com",
      "www-cdn.sun.com",
      "www.sun.com",
      "virtualbox.org",
      "oraclecloud.eu",
      "www.oraclecloud.eu",
      "suitecommerce.com",
      "www.suitecommerce.com",
      "oraclehealth.com",
      "sqlfree.com",
      "oraclefoundation.org",
      "cernerHealth.cm",
      "cernerHealth.co",
      "cernerHealth.co.uk",
      "cernerHealth.net",
      "cernerHealth.uk",
      "cernerHealthCare.com",
      "java.hu",
      "micros.hu",
      "netsuite.hu",
      "oracle.cam",
      "peoplesoft.hu",
      "www.ateam-oracle.com",
      "ateam-oracle.com",
      "oraclehealthfoundation.org",
      "java.com",
      "go.java",
      "netsuitesuiteworld.com",
      "java-stage.com",
      "suiteapp.com",
      "suiteapp.ai",
      "oracle.eu"
    ],
    "days_left": 83,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "138.1.33.162",
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
      "origin": "https://sub.oracle.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://oracle.com:443/"
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
    "webexdomainverification.=d729667e-36b8-4d4a-bbb7-0f3069025573",
    "webexdomainverification.JRJC=6ac35490-0c1a-4729-b3fc-78a568159417",
    "webexdomainverification.=a3652afd-f531-4076-9a45-1e184df3a2d6",
    "webexdomainverification.F00R=81ccb499-274a-447d-a54a-934bb0dafec4",
    "webexdomainverification.=1f146848-946a-45a1-b021-4b3d4ef924d6"
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
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 9633654511136634151065320017458099411,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-2.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-2.crl"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311530130603550407130c526564776f6f642043697479311b3019060355040a13124f7261636c6520436f72706f726174696f6e311330110603550403130a6f7261636c652e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260604000000",
      "not_after": "20261219235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ocomtld-prod.appoci.oracle.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.oracle.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-2.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "cipher_ver": "TLSv1.2",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "elapsed_s": 67.2,
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
