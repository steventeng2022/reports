# Security Audit Report — wix.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wix.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | wix.com |
| Test date | 2026-09-27 00:34 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 5, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=121 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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

### 10. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (4w16w044ztyzyr.wix.com and 6njk758glgs41p.wix.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: stripe-verification=9a57080fa5c5d67942dead568a7b95d81e0b004381ccfda174b91c5a84b3; stripe-verification=acd68941bb2908ddb9252b6af7dfb0bec4c44516bf8ddf6281064d5267d6; stripe-verification=0d2a575bc62dd29de9df29436fb90d8ed6f29050dfae2d211c1ad9aeafbd
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of wix.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but wix.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 87 disallow path(s), e.g. /api/, /blogtemp, /wixblog, /bo/, /editor.jsp
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 199.15.163.133 carries PTR unalocated.163.wixsite.com. for wix.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for wix.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on wix.com lists 1862 <loc> URL(s); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

## Evidence (raw response observations)

```json
{
  "domain": "wix.com",
  "dns": {
    "a": [
      "199.15.163.133"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt3.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "dns3.p03.nsone.net.",
      "dns1.p03.nsone.net.",
      "dns4.p03.nsone.net.",
      "dns2.p03.nsone.net."
    ],
    "caa": [],
    "spf": [
      "stripe-verification=9a57080fa5c5d67942dead568a7b95d81e0b004381ccfda174b91c5a84b370aa",
      "stripe-verification=acd68941bb2908ddb9252b6af7dfb0bec4c44516bf8ddf6281064d5267d6fe16",
      "stripe-verification=0d2a575bc62dd29de9df29436fb90d8ed6f29050dfae2d211c1ad9aeafbd897e",
      "mentimeter-26622928-e74c-4bef-bd86-6fb3ef16da73",
      "google-site-verification=VIxXEU16_I7ytV2OZx7MribDyDrrO8qdo3zN_Z4midI",
      "ZOOM_verify_MfQI7nhORG2Puh-3X5ATPg",
      "openai-domain-verification=dv-pLJ3xAPCIeMa3cC4XNtNDJX2",
      "attio-domain-verification=Z2ET4PUWKCF36X53R79B3D4B",
      "google-site-verification=FXlaz4eC6IRkW2WmIRbIk4CArdmHESk0yNe3AFUDhp0",
      "google-site-verification=mlu2CMylrUqQGNZj8kf-TLOgvFtObPuYG8iDyF40-yw",
      "h1-domain-verification=PcpK2wxKRm5TX3bUxcufNmYpDJfshghw8GwndcysTzykjNsF",
      "stripe-verification=90fcaa8e136e2e6061f8be2b71a3415891ea8673424e9ff92247249c019912e6",
      "tiktok-developers-site-verification=gzeUQu5YG50bjEvjyo0ZfbVZ5j0V999U",
      "hubspot-developer-verification=OGU2OTcxZmMtOTQ5ZS00MmE4LWEwNGMtZDU5ODVjMjFlNzE3",
      "google-site-verification=cPL86MHWzrMGIKsTjOEI-oy3ISSoZhhnwuudVWrhvrU",
      "v=MCPv1; k=ed25519; p=EbQt/aJoTxU91btvOjmJoFgANaxHhXpEw07phT5RZp4=",
      "zapier-domain-verification-challenge=b9a64e2d-2ca9-415d-bd69-cfa2d9fa9907",
      "MS=ms84842189",
      "aO7RBfR",
      "docusign=79f63237-be11-4e2d-b4b4-91ab6dce95fc",
      "google-site-verification=caM2lnCRLah4A1mGepO9qL_hg8cqHdh3UzqMkNMaNAA",
      "msfpkey=5uza2mr5f7gagdu4v6mibe905",
      "google-site-verification=ogdABx45v2ErCVBP-Ms5Wm2fNT-LJq4emfL0AecJZZA",
      "lucidlink-verification=Q6AYQQCN4FGFRCQR0AF47JR318",
      "cloudflare_dashboard_sso=6509b3cf451e0682879ea790c12c0f25",
      "globalsign-domain-verification=pyR6ci6IB7uVAxLPZN5Z7_imdnvGJLhXCcmfs8v5RP",
      "google-site-verification=bgK_1_cVW1tLXaQirTZFxyCNGwebJrSrtxEnhi8nj34",
      "docusign=5e9b707a-aa10-4cc8-8c18-44ba07c7261d",
      "anthropic-domain-verification-wj1991=6IRjBpZdVnL6nplaTY4n69b7J",
      "stripe-verification=e5d336648c47bc8257c95e6b90f8e72cefe71d491fdb5f05e7e91f7dba43b373",
      "c5d403d181be4c99af6bfc33a6b174ef",
      "astro-domain-verification=cmdn44xpt2r0g01n6ltozezn0",
      "google-site-verification=MvlfsFt9kmoBIEA-kfNZGc1DoBWCpDeO2I0BFi2r0Ls",
      "anodot-domain-verification=22a37350bc036e536d9fbb047513c15f1d09de30af60f87c20af295836a05e53",
      "stripe-verification=c20e469bd7bbf272f6048b664b7f9cc406b912f67ad8fa91647eff8350b65f21",
      "amazonses:kmAm6mAq2E1NgyaEam+5i0Mnyf/O2i4kosh3YVJwJZo=",
      "cursor-domain-verification-1tkm1m=rRuMFC1cXEdKxx2xnJVQHycAq",
      "mongodb-site-verification=gdhANZR3xAzZgoC98tNYliiKI87AerWD",
      "atlassian-domain-verification=/0xGMpS1a6Y4hkYjG5Rprk0LKayTNxlYBFefwdxm2FhvHJaFr9MiYUbL0wEu8NYs",
      "openai-domain-verification=dv-FVMlkPb2ttnAtrpY3PbRxymv",
      "google-site-verification=GK0pXfNH9o0j611VmQUTjL4d24lbdaLr4464gb0325s",
      "google-site-verification=WXWCve5A0fdvZG9JuNcYOlPnkIfD5jCwtx-Hz6ky6wA",
      "google-site-verification=tidJNtRp7m6rB1RoNn3WWu94llPGNf69LO5cMRL2aog",
      "canva-site-verification=qnvjScw_870K8yKfi-_rTg",
      "google-site-verification=JO8-pIBHBq2rsYKaFQQDYV0LLq8RbBMxJ3sJmGAvop4",
      "vLXvkpGVsBpywsoGExNq4Y9fpP78GQ",
      "v=spf1 include:wix.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email  ~all",
      "atlassian-domain-verification=csQ4SmhA03xwafLVCnb97huNyHYH1UukzPuDqZGNUAxVncR0FaSIvgm0VUxSpDA9",
      "twilio-domain-verification=833bfa35c546d96f3c57986df3eb723e",
      "_globalsign-domain-verification=hJCPfpeQg9VcjdDQFrVs_lkJML8ynoEnfwBUsQJ6zB",
      "stripe-verification=87df6886f3e159f187fde2e275ec83dc599278c4d7c88dee2391c5879643626a",
      "t9Mb1J4w2JVvj8BbxdSv/0Vq6ijiuUn5uWS/LqkvNkE=",
      "487477444-11657476",
      "wq3kgvs1qvcjxqx95561tx37v6hgssjj",
      "have-i-been-pwned-verification=7bc715f972068147270244a4389abc6d",
      "miro-verification=1400621c6beb4ad13c3ab05208a4bcc4446e4ead",
      "stripe-verification=96483778492eb4f2255ee7fcb447f01413aa413328443b4ef81edadbcbe56af1",
      "Dynatrace-site-verification=501eb6b7-ec68-4d6e-9cff-542d23e861a6__2sdtlct1d5od1saarpf7t3ivro",
      "_globalsign-domain-verification=Fw09cFhmPL_-Bfg6BV5_NkyDEkXJfmQd4uPViX560A",
      "apple-domain-verification=q4AHUtVh9qSoTPfP",
      "google-site-verification=igUuyfBRZoBZQ0BFNepTw5JslX4b4ilhiFYSgT6muOE",
      "bpdvtdlgubb2u4fibokgbtimqm",
      "mixpanel-domain-verify=50fec8a0-784f-4f4d-9e78-0e0a16f8babe",
      "google-site-verification=LlgLpcZTcUwtCuZ6rbFW3qpMhBRXM6TRPLWTaJIz6qo",
      "jamf-site-verification=_Sa01rGeZhiS_fErQgeIfA",
      "google-site-verification=n0cDifZIn0mJu7nixM4mDeq05V87pc2G0idMzBfwpyw",
      "stripe-verification=3d38b8ba77051423fc63beab24fd133e79c48c38c129e6f32a8f31dd1442b257",
      "MS=ms67587784",
      "stripe-verification=c332fc1713103584e6975aff689df49f78df9ea5980c7d124640f12561857924"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@vali.email,mailto:postmaster@wix.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.wix.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR2",
    "notBefore": "Aug  8 11:34:36 2026 GMT",
    "notAfter": "Nov  6 11:34:35 2026 GMT",
    "san": [
      "*.editorx.com",
      "*.wix.com",
      "*.wixsite.com",
      "editorx.com",
      "wix.com",
      "wixsite.com"
    ],
    "days_left": 40,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "199.15.163.133",
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
      "origin": "https://sub.wix.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.wix.com/"
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
  "wildcard_dns": true,
  "apex_txt": [
    "stripe-verification=9a57080fa5c5d67942dead568a7b95d81e0b004381ccfda174b91c5a84b3",
    "stripe-verification=acd68941bb2908ddb9252b6af7dfb0bec4c44516bf8ddf6281064d5267d6",
    "stripe-verification=0d2a575bc62dd29de9df29436fb90d8ed6f29050dfae2d211c1ad9aeafbd",
    "google-site-verification=VIxXEU16_I7ytV2OZx7MribDyDrrO8qdo3zN_Z4midI",
    "openai-domain-verification=dv-pLJ3xAPCIeMa3cC4XNtNDJX2"
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
      "serial": 604318932350562322715033193322124490948777,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://yr2.c.lencr.org/42.crl"
      ],
      "subject_dn": "3112301006035504030c092a2e7769782e636f6d",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303595232",
      "not_before": "20260808113436",
      "not_after": "20261106113435"
    }
  },
  "http2": {
    "robots_disallow": [
      "/api/",
      "/blogtemp",
      "/wixblog",
      "/bo/",
      "/editor.jsp",
      "/noflashhtml",
      "/siteBackHtml",
      "/wix/",
      "/wixpress/",
      "/wixdemo/",
      "/wix-editor/",
      "/editor2.jsp",
      "/flash/",
      "/flash-templates/",
      "/website-template/view/flash/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "unalocated.163.wixsite.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.wix.com/",
    "http_status": 301,
    "p404_status": 301,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=121 ; includeSubDomains",
    "sitemap": {
      "urls": 1862,
      "indexes": 0
    },
    "crl": {
      "url": "http://yr2.c.lencr.org/42.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "elapsed_s": 36.1,
  "rechecked": "2026-09-27 00:08 UTC"
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
- Findings are reported against the public program scope; submission through the program tracker is pending.
