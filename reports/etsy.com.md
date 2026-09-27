# Security Audit Report — etsy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://etsy.com/ |
| Bug bounty program | Etsy |
| Listed scope domain | etsy.com |
| Test date | 2026-09-27 01:18 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 8, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 13 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 14 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 15 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 16 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 17 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 20 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 21 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |
| 22 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 13. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): mail. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 14. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.etsy.com/.well-known/mta-sts/policy.txt -> 403
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 15. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (712hyv60zft3e9.etsy.com and qop3jtzs5il3el.etsy.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 16. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=xfkrv3yRwA5GGm0E4l5RlcNKTqVD8KAYsYdCYTBMF0; segment-site-verification=qK8Hs2slX9yMAAiKpgMoNP6bJCKq0cqQ; adobe-idp-site-verification=1858581c5ab657f77e067d14de03dd297c85f0b6b2916dbe0ade
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 17. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2025q4 -> http-400
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1681 disallow path(s), e.g. /, /people, /uk/people, /au/people, /ca/people
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for etsy.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 20. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The etsy.com certificate lists an AIA OCSP responder (http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2025q4) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 21. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to etsy.com negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

### 22. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on etsy.com identify the edge as Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

## Evidence (raw response observations)

```json
{
  "domain": "etsy.com",
  "dns": {
    "a": [
      "151.101.1.224",
      "151.101.129.224",
      "151.101.193.224",
      "151.101.65.224"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx2.googlemail.com (pref 40)",
      "aspmx3.googlemail.com (pref 50)",
      "aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "ns-162.awsdns-20.com.",
      "ns-1264.awsdns-30.org.",
      "dns1.p03.nsone.net.",
      "dns3.p03.nsone.net."
    ],
    "caa": [],
    "spf": [
      "_globalsign-domain-verification=xfkrv3yRwA5GGm0E4l5RlcNKTqVD8KAYsYdCYTBMF0",
      "MS=ms91667443",
      "segment-site-verification=qK8Hs2slX9yMAAiKpgMoNP6bJCKq0cqQ",
      "adobe-idp-site-verification=1858581c5ab657f77e067d14de03dd297c85f0b6b2916dbe0adeca4fac539e6b",
      "wrike-verification=NDMwNDc4NDo3YzVlMGVmM2RhZGU0NjRkZTIxZTBjYmU5Mjc2NGZmODRmNzVhMDc2NjRmMTI0NThhYzlhZTdhMzhkNzkyY2Uw",
      "lucidlink-verification=HYZGQ2NMESYDAVG1GR5EJX21Z0",
      "miro-verification=31250d3fe2c000cf1f892588d27dcf9eeb6afdd8",
      "stripe-verification=fe491048e654bcc35d8f194964540604a3a4108e3191ffd27a9ea4c232d5bcf1",
      "facebook-domain-verification=j81l6m6391dika9nlbuh2c8ji9nhye",
      "anthropic-domain-verification-nehbw6=4taelnzAjM6NVkhm1rylyYZ8r",
      "monday-com-verification=bG-_DMl97UjUXdEr36_aoOlymHnNMGiZ9z_UM8h7t20",
      "datadome-domain-verify=BNtk7vonAvB8fhBLjp0E2orOzns71WB1",
      "v=spf1 ip4:66.3.159.0/24 ip4:192.147.0.0/24 ip4:173.46.67.72/29 ip4:192.147.1.0/24 ip4:38.106.64.0/24 ip4:38.76.1.0/24 ip4:38.76.2.0/24 ip4:162.220.28.32/27 ip4:162.220.28.64/28 ip4:208.74.204.0/22 ip4:46.19.168.0/23 include:servers.mcsv.net include:mail.",
      "zendesk.com include:amazonses.com include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com a:web.q4press.com include:cvent-planner.com include:mail.clinchtalent.com include:spf.redpoints.com -all",
      "docker-verification=40052c18-7a84-4d01-a294-9fed0866066e",
      "docusign=9866d46c-c0b0-47c6-a98e-c6381eb4ccc6",
      "apple-domain-verification=qgAwoHpdlhEv-3QiQ3G11S5xHj60JbTSzecxszntlvo",
      "stripe-verification=5e8773ee85575b784fc2a6868da2b17b165e2e59f62d067f77bfd40c0ad5cdc5",
      "fastly-domain-delegation-svi5ebiqbg4tbn-20251029",
      "openai-domain-verification=dv-kBkaf6OFwgohxPZc4YIjOD6t",
      "stripe-verification=660c4cdde58756c254bc46c26b92b6232ebc140156e6d2ba74cbb988b283b5ae",
      "jamf-site-verification=lUaUDNLb-GDzmbIbaCg_lg",
      "cursor-domain-verification-vyqnwm=JyRGj2Bcnbk8QqNAclaAE8mHY",
      "pinterest-site-verification=b92965d84ebb1103548fbd23e39baf66",
      "bugcrowd-verification=460ceee75155fa4965c62123bc9cd182",
      "MS=61C0D53B132406B96613AF941D1FFB83A6CFCD73",
      "onetrust-domain-verification=9f4716cb45f046429764b34174392ce2",
      "google-site-verification=mpVLpWjH_tjbc5eK6pmVTZjq4xmHhzoE3crE0rKFULs",
      "atlassian-domain-verification=cMcfcaBm3JNaxKiO2fok5oOn20qbqxLmjQdFrsLV25SQj8l5hTkX/pb21NqLPLP0"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc@etsy.com; ruf=mailto:dmarc@etsy.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=*.etsystatic.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2025 Q4",
    "notBefore": "Nov  3 15:09:45 2025 GMT",
    "notAfter": "Dec  5 15:09:44 2026 GMT",
    "san": [
      "*.etsystatic.com",
      "api-origin.etsy.com",
      "api.etsy.com",
      "m.etsy.com",
      "openapi.etsy.com",
      "www.etsy.com",
      "etsy.com",
      "openapi-staging.etsy.com"
    ],
    "days_left": 69,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "151.101.1.224",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.etsy.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.etsy.com/"
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
    "_globalsign-domain-verification=xfkrv3yRwA5GGm0E4l5RlcNKTqVD8KAYsYdCYTBMF0",
    "segment-site-verification=qK8Hs2slX9yMAAiKpgMoNP6bJCKq0cqQ",
    "adobe-idp-site-verification=1858581c5ab657f77e067d14de03dd297c85f0b6b2916dbe0ade",
    "wrike-verification=NDMwNDc4NDo3YzVlMGVmM2RhZGU0NjRkZTIxZTBjYmU5Mjc2NGZmODRmNzVhM",
    "lucidlink-verification=HYZGQ2NMESYDAVG1GR5EJX21Z0"
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
      "aia_ocsp": "http://ocsp.globalsign.com/ca/gsatlasr3dvtlsca2025q4",
      "serial": 1565224459863225002521978909495044232,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.globalsign.com/ca/gsatlasr3dvtlsca2025q4.crl"
      ],
      "subject_dn": "3119301706035504030c102a2e657473797374617469632e636f6d",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312e302c06035504031325476c6f62616c5369676e2041746c617320523320445620544c532043412032303235205134",
      "not_before": "20251103150945",
      "not_after": "20261205150944"
    },
    "ocsp": "http-400"
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/people",
      "/uk/people",
      "/au/people",
      "/ca/people",
      "/de-en/people",
      "/dk-en/people",
      "/fi-en/people",
      "/hk-en/people",
      "/ie/people",
      "/il-en/people",
      "/in-en/people",
      "/no-en/people",
      "/nz/people",
      "/se-en/people"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.etsy.com/",
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
      "url": "http://crl.globalsign.com/ca/gsatlasr3dvtlsca2025q4.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "cipher_ver": "TLSv1.2",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "cdn": [
      "Fastly"
    ]
  },
  "elapsed_s": 28.6,
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
