# Security Audit Report — udemy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://udemy.com/ |
| Bug bounty program | Udemy |
| Listed scope domain | udemy.com |
| Test date | 2026-09-27 01:36 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 4, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 9 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 13 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 14 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 15 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 16 | info | HTML1 | Security policy set via <meta http-equiv> | CWE-1021 |
| 17 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 18 | info | H25 | server-timing response header exposed | CWE-200 |
| 19 | info | HTML14 | Public root document marked noindex | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.142.237:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.142.237:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.udemy.com/.well-known/mta-sts/policy.txt -> 403
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 9. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (gnc5oz221wxgrr.udemy.com and lx87gpuing9lt2.udemy.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=0Gl3_FzqmUkS2NHg_Wd5pmGiSmt_Jk4MVnaCiDbhDnY; apple-domain-verification=MntOsncD5C5BxosV; google-site-verification=4E_wLzpH4XLGfUSem4QVA6mUpRJDjvZ03pG1jU56hNM
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of udemy.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of udemy.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 13. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on udemy.com indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 14. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkc6bzwyeb5e9b.html -> 403; error page/headers match: Cloudflare.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 15. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for udemy.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 16. [INFO] Security policy set via <meta http-equiv> (`HTML1`)

- **CWE:** CWE-1021
- **Detail:** HTML root of udemy.com declares via meta tags: content-security-policy; meta-set policies have limited browser support and are easier to override than response headers.
- **Recommendation:** Prefer response headers and keep any meta declarations consistent with them.

### 17. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of udemy.com sends a CSP but contains 1 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 18. [INFO] server-timing response header exposed (`H25`)

- **CWE:** CWE-200
- **Detail:** The root response of udemy.com sends server-timing (chlray;desc="a416c6f8ea924a96"); server/edge processing metrics are disclosed to any client.
- **Recommendation:** Restrict server-timing to authenticated/debug contexts if the internals are sensitive.

### 19. [INFO] Public root document marked noindex (`HTML14`)

- **CWE:** CWE-200
- **Detail:** The root document of udemy.com is marked noindex (meta robots or X-Robots-Tag); a public homepage that is not indexable is a posture anomaly worth reviewing.
- **Recommendation:** Confirm the noindex directive is intentional.

## Evidence (raw response observations)

```json
{
  "domain": "udemy.com",
  "dns": {
    "a": [
      "104.16.142.237",
      "104.16.143.237"
    ],
    "aaaa": [
      "2606:4700::6810:8eed",
      "2606:4700::6810:8fed"
    ],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "pete.ns.cloudflare.com.",
      "anna.ns.cloudflare.com."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=0Gl3_FzqmUkS2NHg_Wd5pmGiSmt_Jk4MVnaCiDbhDnY",
      "_nbghqs48lzt0emavhip5o2dyy5kb0xy",
      "apple-domain-verification=MntOsncD5C5BxosV",
      "v=spf1 include:_spf.google.com include:mktomail.com include:spf.mtasv.net include:mail.zendesk.com include:_spf.salesforce.com -all",
      "google-site-verification=4E_wLzpH4XLGfUSem4QVA6mUpRJDjvZ03pG1jU56hNM",
      "google-site-verification=mSmGycRVFusrCec4blSh608oUai-y0AumEuI3OlaGBo",
      "citrix-verification-code=6b798901-86c6-452c-a3ea-ed718cab39bd",
      "zero-path-domain-verification-6e9hdw=BtrY4vZKLJdp2XlFj1sE4FFVG",
      "miro-verification=f165badb21a511b048a7f7a9fba3352c0db8b09b",
      "atlassian-domain-verification=iztR9OQCHGIVBm5w5PmFPf1nTaqiOROSuNTF9Kv0idnfzCBmAsbfwGEF2aOK+yo4",
      "stripe-verification=e2909d7f06f271e18ace56ef06db7b552e6692c312adfedaf6cea1a2e0d63125",
      "twilio-domain-verification=8e64b1bb044ab98ebbd3638c1babb25a",
      "stripe-verification=e006b01ab77ebbe2e6c509a4e2280540bfea979f8c49ed3efd225004aa2f6292",
      "globalsign-domain-verification=K9ZBZYNiNsNNOiaY2Tbjn-Bfe0dWwAwpstKoOOVJWO",
      "mint-mcp-domain-verification-3p7dva=FgfX3ooe8zSPrzYaM0SEJjugO",
      "apple-domain-verification=IEscmDl7jHBZDO_dBAG0xMjbBbPxomU_9rqwksKrNmk",
      "onetrust-domain-verification=2a6df466515246c4a7c37104f55a82b8",
      "stripe-verification=4d955ddab5b0fc6cf1931b41935e45f7997f3b13677532d11e6a90b58f5156aa",
      "MS=ms39886121",
      "google-site-verification=lKnsAORvM6iM1XErS9RH0TeVGG7VfTb5ST7PGx1AQ-w",
      "atlassian-domain-verification=YpSV2agr6k+w5lkm2ml8m8/N+xCTPcXjTKwDomeoJJTrgnmCoeRyXs/U576G4Cz2",
      "jamf-site-verification=L9yfsaaKM7FxdBtc5kWk6g",
      "stripe-verification=a4f63d60cd50bfe9f3b2c2d8aa55bc596a98ab6e0f0f2e9d798c6939ece90b90",
      "google-site-verification=RuYIvfeP5e2eBgQzIaky9XuiCkkrVE2KUBULndTtFE4",
      "google-site-verification=Ca1sgMRin5VW1yxjUntivQ3-RySo8SmJcWR6zgFW_w0",
      "google-site-verification=KR2k8MUNPfIO05_bn2-YYMLxVUsnkD-ptX-lBLPmz6M",
      "docusign=d078f828-536c-4ce3-a867-b26ad811bb8a",
      "cursor-domain-verification-pae8cg=8gFowcF4OpBSeYJTIw0GYPFvL",
      "stripe-verification=8ad760d1d60c9bbd83b03ed7fe20a10682f7d65774aa9db13a0b524e51cefe2c",
      "google-site-verification=c7RTHsaBu_LU5KgIFuPCWa5yxuTrkOGYtKaYt85mrq8",
      "google-site-verification=ld8CL_RjIj_FPsIdElHPqkhOMJ8Rixk1y7-s0Opi-90",
      "prowly-verification=bebd281d32a3e1b8140345e1f876f82eff2ba617d782c6206e7c21fd9fdbd880",
      "docusign=206e891a-5b22-4d4c-9a10-85066ba89160",
      "pendo-domain-verification=595ba9d5-03ac-4aee-b50f-168214b6a32a",
      "loom-site-verification=f173ba1cc44648d0ac2bbd0919868a6b",
      "_globalsign-domain-verification=9UioyPO0_F2Epyd3gGV5_VklXzoibTukD_jkbZPw43",
      "adobe-idp-site-verification=e54c98a1c7f23b54b8ac4b7b75952259c173d7bfba731f72db60eb7ad4e63d97",
      "_globalsign-domain-verification=oJsQtL3M8axaRGjlRJ4BstY+1TfWDryoeAouwRxay7A=",
      "stripe-verification=54fa1ebf13b6990c87e17caffc4829d9600d3bd0ca60b24e6bf9ae530baf37f3",
      "google-site-verification=IKMJeRfamsooHAMaTQdFDaQ4MsfeW1Nr6F7DPDEkycg",
      "canva-site-verification=Ng9bmmu7vJyWHYrTk_wUZw",
      "cloudhealth=8d6a3d7f-ed91-4280-8422-b4b27b3dfcda",
      "globalsign-domain-verification=Bo6R5k9s2Zwdk5OoeybGk6L2EHx_oV1TqLgGiMR4IQ",
      "stripe-verification=5808adfa0c91e8dfe4ecd14f20c22ba0d54b6e8b71b23a5eada978511a246e1a",
      "openai-domain-verification=dv-ncbISx7kF83lZ69Xc97AoraD",
      "stripe-verification=044c7ed24abd68184b0a86b00dbd47b87d1db3a5eb2ee132df5131bfc6fe29d1",
      "google-site-verification=FZsUD-xuwip73XO7XfuX-4kDEY-_Qel0klHmmu6CB5k",
      "anthropic-domain-verification-8xcn1b=XJ2EZ4D0KXPEyEAZU21FX1D94",
      "globalsign-domain-verification=fB1XzR_1Hvbw32pP6EbLFlB9r4pxcc86XOgA7B7DyV"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-udemy@udemy.com; ruf=mailto:dmarc-udemy@udemy.com; rf=afrf; fo=1; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=udemy.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 11 02:43:04 2026 GMT",
    "notAfter": "Dec 10 03:43:02 2026 GMT",
    "san": [
      "udemy.com",
      "*.udemy.com"
    ],
    "days_left": 74,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.16.142.237",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "udemy.com",
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
      "origin": "https://sub.udemy.com",
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
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=0Gl3_FzqmUkS2NHg_Wd5pmGiSmt_Jk4MVnaCiDbhDnY",
    "apple-domain-verification=MntOsncD5C5BxosV",
    "google-site-verification=4E_wLzpH4XLGfUSem4QVA6mUpRJDjvZ03pG1jU56hNM",
    "google-site-verification=mSmGycRVFusrCec4blSh608oUai-y0AumEuI3OlaGBo",
    "citrix-verification-code=6b798901-86c6-452c-a3ea-ed718cab39bd"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "serial": 296467501980592886112427993156945397822,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/we1/JHyEH4xCeMU.crl"
      ],
      "subject_dn": "31123010060355040313097564656d792e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531",
      "not_before": "20260911024304",
      "not_after": "20261210034302"
    }
  },
  "x12": {
    "status": 403
  },
  "x13": {
    "root_status": 403,
    "http_status": 403,
    "p404_status": 403,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 403,
    "crl": {
      "url": "http://c.pki.goog/we1/JHyEH4xCeMU.crl",
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
    "server_timing": "chlray;desc=\"a416c6f8ea924a96\"",
    "noindex": true
  },
  "elapsed_s": 4.9,
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
