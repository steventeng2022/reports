# Security Audit Report — pandora.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pandora.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | pandora.com |
| Test date | 2026-09-27 01:29 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **25** (High: 0, Medium: 0, Low: 5, Info: 20)

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
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 18 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 19 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 20 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 21 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 22 | info | WK2 | OIDC discovery document published | CWE-200 |
| 23 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |
| 24 | info | CT1 | 45 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 25 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache
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
- **Detail:** Header reveals: Apache
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: drift-domain-verification=7dcb7704b70c0f98d5f1188a55e7fe4c1a0d0a5c8474f0b5d7feaf; shopify-verification-code=QZZP4RdLtXmhnyVfqGJxOtDrTJwdHv; zapier-domain-verification-challenge=0c6f32b8-f62f-4918-aa85-11e2476e37ec
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but pandora.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 12 disallow path(s), e.g. /, /, /api/v1/playback/, /api/v1/event/, /api/v1/action/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 199.116.164.229 carries PTR www-dc6.gslb.pandora.com. for pandora.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkpomdcab1smn7.html -> 404; error page/headers match: Apache.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 18. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on pandora.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 19. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for pandora.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 20. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The pandora.com certificate lists an AIA OCSP responder (http://status.thawte.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 21. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on pandora.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of pandora.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 22. [INFO] OIDC discovery document published (`WK2`)

- **CWE:** CWE-200
- **Detail:** /.well-known/openid-configuration on pandora.com is live (issuer: https://www.pandora.com); the OIDC endpoint configuration (authorization/token/JWKS URLs) is publicly disclosed.
- **Recommendation:** Confirm the published OIDC metadata matches the deployed identity architecture.

### 23. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to pandora.com negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

### 24. [INFO] 45 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: blog.pandora.com, help.pandora.com, www.help.pandora.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 25. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: www.help.pandora.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "pandora.com",
  "dns": {
    "a": [
      "199.116.164.229"
    ],
    "aaaa": [
      "2620:106:e001:f00d::e7"
    ],
    "cname": null,
    "mx": [
      "mx0b-0051e301.pphosted.com (pref 3)",
      "mx0a-0051e301.pphosted.com (pref 3)"
    ],
    "ns": [
      "dns2.p05.nsone.net.",
      "dns1.p05.nsone.net.",
      "ns2.pandora.com.",
      "ns4.pandora.com."
    ],
    "caa": [],
    "spf": [
      "drift-domain-verification=7dcb7704b70c0f98d5f1188a55e7fe4c1a0d0a5c8474f0b5d7feaf2a17ddaf8b",
      "shopify-verification-code=QZZP4RdLtXmhnyVfqGJxOtDrTJwdHv",
      "zapier-domain-verification-challenge=0c6f32b8-f62f-4918-aa85-11e2476e37ec",
      "stripe-verification=46db797e734d25037c8a1966048d4d0a26f34600f23375c9ab8f1b327dc5b023",
      "webexdomainverification.4C675B8AC948B136E053AB06FC0A3F65=c8670c99-cf44-4da5-a347-0e378903bd08",
      "airtable-verification=92001d7da07339e0b17a973f2faaa71b",
      "stripe-verification=9afcd9b96859582b2edf39640758f0a7ca9bbbc04fc0acd4eda69d964978923b",
      "anthropic-domain-verification-cehw0s=Q6GJ2C5R4orf8oDA6ntjc8jiI",
      "onetrust-domain-verification=52ed295d1cc747c8b4a923ee0d52bb89",
      "stripe-verification=9ac87819ed1e8c4c43fb4806e46ee7ac5135b3ac5eb80fc1ceca8ec0bf1fd7c0",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
      "bugcrowd-verification=9224a322abc2e3e36bf6aef0cf1d2977",
      "_9ax3ucie5r4ihbdbsi4tuuy6jex2x7y",
      "jetbrains-domain-verification=1erv1ckkr599h7o8n4nnatntx",
      "/4SPMALLPHvERsW46Wt5HeyzV7tWXyqSCVio3D+e46JOIQ1Lx4ayzLacYa2Nani5VZLIsG6QzSbAxqQorgT8Pw==",
      "atlassian-domain-verification=suALAhcWjB6Eq0SuX424kLGZ8kMs8yfsj4LDWz6QHyorTk7BzUFfbXXgI4pyznZy",
      "stripe-verification=7700e585bc13984d32505fc0743dd1742a7b00ab8f89fd43edbb64b7e86eb3df",
      "docker-verification=09663cec-b2f4-4ce1-92a8-9bdc828efd88",
      "google-site-verification=ZmhaVAHHT8AaKg7hP9Mmd3mrk8AMaSh90uPg77P-Gyo",
      "liveramp-site-verification=3auN45Pf2H9Obu6SoSX-izAUSRjBnVPQbEnXgyJK8MQ",
      "stripe-verification=a2efa4b173f85f9b16a2fe262a5d7fa95a0b18f0ba884723050e917033a5af28",
      "google-site-verification=7rxKTJwaOBuE3vNSi4Yl0fG04rCK2xr4rYvsy2yMPgs",
      "stripe-verification=eb9cdfa80af377c6421610f8153fd4151acb46fe9414e78a4ce90c2d0d82f93a",
      "openai-domain-verification=dv-MtwM2KzO6fmabwatU3A5suMJ",
      "stripe-verification=47c5a8c489eea6dc578dfd12d08d3b7accf87c7729c8958144a35f50361cc92a",
      "make-domain-verification=0d44a7b3-d8f7-4bc0-bf24-53609a1f2fe7",
      "facebook-domain-verification=nn42grx580r7pjlyzjzxv3mrnn5lpx",
      "MS=ms48003601",
      "stripe-verification=b7edf88636d477ae4501df1dbebcda1b9f3eb5f895d94a5dcaa35715fd8525a7",
      "stripe-verification=eef61a09f3c1c4f6890acce9bff70c102c0c389cc77e9970a3b2a17e582f3b27",
      "apple-domain-verification=GVC0xaZwt2Sv9Ivm",
      "stripe-verification=6151a13c2e26e26166de3da9cbc43b4b418109e806e0fef941a34da28edc06ca",
      "Pandora",
      "monday-com-verification=Y7tba9sDRtLGwJrmA-A2bxVKMIOuhp5g9YnzcMJifOo"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Oakland, organizationName=Pandora Media LLC, commonName=*.pandora.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=Thawte TLS RSA CA G1",
    "notBefore": "Sep 15 00:00:00 2026 GMT",
    "notAfter": "Apr  1 23:59:59 2027 GMT",
    "san": [
      "*.pandora.com",
      "pandora.com"
    ],
    "days_left": 186,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "199.116.164.229",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Apache"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.pandora.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.pandora.com"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 45,
    "notable": [
      "blog.pandora.com",
      "help.pandora.com",
      "www.help.pandora.com"
    ],
    "sample": [
      "ac.pandora.com",
      "ads.pandora.com",
      "advertising.pandora.com",
      "blog.pandora.com",
      "brandadvertising-sandbox.pandora.com",
      "brandadvertising.pandora.com",
      "brands.pandora.com",
      "bread2.pandora.com",
      "ce.pandora.com",
      "community.pandora.com",
      "dam.pandora.com",
      "delivery.pandora.com",
      "design.pandora.com",
      "device-tuner.pandora.com",
      "engineering.pandora.com",
      "esb-dev-int.pandora.com",
      "esb-dev.pandora.com",
      "esb-int.pandora.com",
      "esb.pandora.com",
      "google-receiver.cs.pandora.com"
    ],
    "dangling": [
      "www.help.pandora.com"
    ]
  },
  "apex_txt": [
    "drift-domain-verification=7dcb7704b70c0f98d5f1188a55e7fe4c1a0d0a5c8474f0b5d7feaf",
    "shopify-verification-code=QZZP4RdLtXmhnyVfqGJxOtDrTJwdHv",
    "zapier-domain-verification-challenge=0c6f32b8-f62f-4918-aa85-11e2476e37ec",
    "stripe-verification=46db797e734d25037c8a1966048d4d0a26f34600f23375c9ab8f1b327dc5",
    "webexdomainverification.4C675B8AC948B136E053AB06FC0A3F65=c8670c99-cf44-4da5-a347"
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
      "aia_ocsp": "http://status.thawte.com",
      "serial": 9794865021480349108708987917530996658,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://cdp.thawte.com/ThawteTLSRSACAG1.crl"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e69613110300e060355040713074f616b6c616e64311a3018060355040a131150616e646f7261204d65646961204c4c433116301406035504030c0d2a2e70616e646f72612e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d311d301b0603550403131454686177746520544c5320525341204341204731",
      "not_before": "20260915000000",
      "not_after": "20270401235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/",
      "/api/v1/playback/",
      "/api/v1/event/",
      "/api/v1/action/",
      "/restricted",
      "/content/",
      "/backstage/",
      "/restricted",
      "/content/",
      "/backstage/",
      "/api/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "www-dc6.gslb.pandora.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.pandora.com",
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "stapling": "not-offered",
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
      "url": "http://cdp.thawte.com/ThawteTLSRSACAG1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "cipher_ver": "TLSv1.2",
    "root_status": 301,
    "oidc": "https://www.pandora.com"
  },
  "x16": {
    "root_status": 301
  },
  "elapsed_s": 50.5,
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
