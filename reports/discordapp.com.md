# Security Audit Report — discordapp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://discordapp.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | discordapp.com |
| Test date | 2026-09-27 02:25 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **26** (High: 0, Medium: 0, Low: 6, Info: 20)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 19 | low | RD2 | HTTPS root redirects to a different domain | CWE-200 |
| 20 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 21 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 22 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 23 | info | WK2 | OIDC discovery document published | CWE-200 |
| 24 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 25 | info | HTML14 | Public root document marked noindex | CWE-200 |
| 26 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.133.233:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.133.233:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 12. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.discordapp.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: adobe-idp-site-verification=954e966634e7f12b8a9a2876a989bf5e7f5050a5192c3f529b99; stripe-verification=b449d3730bb78d03e0744aa61ae3fa2f35f80572bff9e48ad9a192750829; zapier-domain-verification-challenge=d87a2680-bf27-4b61-8174-5ceed32bb8c7
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of discordapp.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 46 disallow path(s), e.g. /channels, /channels/, /verify, /verify/, /reset
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on discordapp.com indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 19. [LOW] HTTPS root redirects to a different domain (`RD2`)

- **CWE:** CWE-200
- **Detail:** https://discordapp.com/ answered 301 with Location: https://discord.com/ (cross-domain handoff at the entry point).
- **Recommendation:** Review the cross-domain redirect; it discloses the real entry point and can be abused in open-redirect-style flows.

### 20. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on discordapp.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 21. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for discordapp.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 22. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on discordapp.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 23. [INFO] OIDC discovery document published (`WK2`)

- **CWE:** CWE-200
- **Detail:** /.well-known/openid-configuration on discordapp.com is live (issuer: https://discord.com); the OIDC endpoint configuration (authorization/token/JWKS URLs) is publicly disclosed.
- **Recommendation:** Confirm the published OIDC metadata matches the deployed identity architecture.

### 24. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of discordapp.com carries alt-svc h3=":443"; ma=86400; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 25. [INFO] Public root document marked noindex (`HTML14`)

- **CWE:** CWE-200
- **Detail:** The root document of discordapp.com is marked noindex (meta robots or X-Robots-Tag); a public homepage that is not indexable is a posture anomaly worth reviewing.
- **Recommendation:** Confirm the noindex directive is intentional.

### 26. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of discordapp.com contains wildcard SAN entry(ies) *.discordapp.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

## Evidence (raw response observations)

```json
{
  "domain": "discordapp.com",
  "dns": {
    "a": [
      "162.159.133.233",
      "162.159.134.233",
      "162.159.129.233",
      "162.159.130.233",
      "162.159.135.233"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "aspmx3.googlemail.com (pref 10)"
    ],
    "ns": [
      "gabe.ns.cloudflare.com.",
      "sima.ns.cloudflare.com."
    ],
    "caa": [],
    "spf": [
      "adobe-idp-site-verification=954e966634e7f12b8a9a2876a989bf5e7f5050a5192c3f529b9917cc4a7d1436",
      "stripe-verification=b449d3730bb78d03e0744aa61ae3fa2f35f80572bff9e48ad9a1927508291ea1",
      "zapier-domain-verification-challenge=d87a2680-bf27-4b61-8174-5ceed32bb8c7",
      "adobe-sign-verification=d19200aacd69c1b8e10cd1a5b47c91c3",
      "MS=CD44642CAC1658ABE588B1F34173984181355D4E",
      "atlassian-domain-verification=JNe2Ze7P8p623k8f7xRaHDyQWb6VzLxjFga1tu8M7lmVXC0bo1XgdnEsYuGIRFHv",
      "google-site-verification=jtVaxAcfspCN94ECrH12n9XJhdqO6Y2j2u3eh1XsApE",
      "hubspot-domain-verification=YmIxMDNhZDEtMzI3Mi00ZWNjLTk4MTYtNmViZGU5NzYyZDM5",
      "5508A8F48F",
      "slack-domain-verification=wmXS8pleSDJ3LgREcHasvMfdkHmBbUvNI6nHNnJl",
      "google-site-verification=PmQRNDYVKwgF3tM6HulK5Fmmna3DSKklkjl-epmhplA",
      "google-site-verification=ihjYpERVTt6QLWL2IBBLsEZroHPjP3vVQHQG97oXZlI",
      "v=spf1 include:_spf.google.com include:mail.zendesk.com include:sendgrid.net include:3885857.spf06.hubspotemail.net include:_spf.salesforce.com -all",
      "jamf-site-verification=xf0BRLPJ0fkW9oZxiDbxaQ",
      "notion_verify_A}38XvVG2tiA3b6w4kU89}p~hasV-%G^E8U0.Evvp?^a==pC1]12+eXq]BgW+%hmodpfn]",
      "logmein-verification-code=e675be17-2988-4b0b-9e19-d6793fc28655",
      "docker-verification=f765b7ff-5ce5-4f27-b00a-28091eddacce",
      "onetrust-domain-verification=3e11024ff11441678e3d59aa6b3a87bc",
      "google-site-verification=27NMadvvj0pSQl1hkMaX3X5bwpjdFmE_FvX-MAgdLBE",
      "apple-domain-verification=xPWro2NHlvCQs7LI",
      "gc-ai-domain-verification-h4p9zv=mTSLyVQqkAlNuctKXdWWZ7MLC",
      "HjRfQW6OV2YOkDOgNju3gYI0_cx9H1iF",
      "google-site-verification=DGERr7gTRtGPVmghE_qE_w3X2kyTXdqiDVR2pBDpndQ",
      "jetbrains-domain-verification=b5av2j0mg51z6vn0dpigrxbxx",
      "dust-domain-verification-kz9236=gJamMWiktWPTDezEQ9uvTDzyS",
      "logmein-verification-code=2d4b306a-e291-4dc9-a09f-2cc3277288cc",
      "loom-site-verification=3b8db7a74102494ba9569c862bbc5587",
      "autodesk-domain-verification=2sh4O6xiIc4ReP9Aee8h",
      "dropbox-domain-verification=66jnk5y945ew",
      "stripe-verification=1d56fec5a0f745dabfbe48592806853324fe50a8d4448c10e524136d1fac1cae"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:eb13ef68c6894cf0bc517e8303852ee3@dmarc-reports.cloudflare.net;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=discordapp.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 28 22:09:52 2026 GMT",
    "notAfter": "Nov 26 23:09:41 2026 GMT",
    "san": [
      "discordapp.com",
      "*.discordapp.com"
    ],
    "days_left": 60,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "162.159.133.233",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
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
      "domain": "discordapp.com",
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
      "origin": "https://sub.discordapp.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://discordapp.com/"
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
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "adobe-idp-site-verification=954e966634e7f12b8a9a2876a989bf5e7f5050a5192c3f529b99",
    "stripe-verification=b449d3730bb78d03e0744aa61ae3fa2f35f80572bff9e48ad9a192750829",
    "zapier-domain-verification-challenge=d87a2680-bf27-4b61-8174-5ceed32bb8c7",
    "adobe-sign-verification=d19200aacd69c1b8e10cd1a5b47c91c3",
    "atlassian-domain-verification=JNe2Ze7P8p623k8f7xRaHDyQWb6VzLxjFga1tu8M7lmVXC0bo1"
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
      "serial": 284532422232787124917009775493431961887,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/we1/IncWY0vTlR0.crl"
      ],
      "san": [
        "discordapp.com",
        "*.discordapp.com"
      ],
      "subject_dn": "311730150603550403130e646973636f72646170702e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531",
      "not_before": "20260828220952",
      "not_after": "20261126230941"
    }
  },
  "http2": {
    "robots_disallow": [
      "/channels",
      "/channels/",
      "/verify",
      "/verify/",
      "/reset",
      "/reset/",
      "/authorize-ip",
      "/authorize-ip/",
      "/reject-ip",
      "/reject-ip/",
      "/reject-mfa",
      "/reject-mfa/",
      "/oauth2",
      "/oauth2/",
      "/api"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://discord.com/",
    "http_status": 301,
    "p404_status": 301,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "security_txt": "/.well-known/security.txt",
    "crl": {
      "url": "http://c.pki.goog/we1/IncWY0vTlR0.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301,
    "oidc": "https://discord.com"
  },
  "x16": {
    "root_status": 301,
    "alt_svc": "h3=\":443\"; ma=86400",
    "noindex": true
  },
  "x17": {
    "wildcard_san": [
      "*.discordapp.com"
    ]
  },
  "elapsed_s": 7.9,
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
