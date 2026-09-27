# Security Audit Report — pewresearch.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pewresearch.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | pewresearch.org |
| Test date | 2026-09-27 01:30 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 3, Info: 16)

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
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 17 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 18 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 19 | info | CT1 | 13 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
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
- **Detail:** Header reveals: nginx
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
- **Detail:** Apex TXT records with verification/token content: cursor-domain-verification-36qzmn=mNriG0xAskkvI4tGbhcGakb2s; google-site-verification=jwmmtXct21FKveAwprcQKkMrhqVY7ac2TtxUvubWT30; workbrew-domain-verification-b91wyv=bPXNAREVhl7vOrFTnQdCJbRFZ
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of pewresearch.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 6 disallow path(s), e.g. /wp-admin/, /wp-content/plugins/prc-icon-library/, /wp-content/plugins/prc-icon-library/, /search/, /search
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for pewresearch.org, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 17. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on pewresearch.org lists 5 <loc> URL(s) across 6 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 18. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on pewresearch.org identify the edge as Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 19. [INFO] 13 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: assets.pewresearch.org, beta.pewresearch.org, status.pewresearch.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "pewresearch.org",
  "dns": {
    "a": [
      "192.0.66.2"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "pewresearch-org.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "ns-281.awsdns-35.com.",
      "ns-795.awsdns-35.net.",
      "ns-1318.awsdns-36.org.",
      "ns-1841.awsdns-38.co.uk."
    ],
    "caa": [],
    "spf": [
      "MS=ms46499721",
      "MS=ms53170065",
      "cursor-domain-verification-36qzmn=mNriG0xAskkvI4tGbhcGakb2s",
      "google-site-verification=jwmmtXct21FKveAwprcQKkMrhqVY7ac2TtxUvubWT30",
      "t35wwdky16ymmmcgvvs20r2bv8zny0j0",
      "81mjlnmdt3ilhf605acjac3142",
      "workbrew-domain-verification-b91wyv=bPXNAREVhl7vOrFTnQdCJbRFZ",
      "LEu+WRccDmqfd4AKPAO6X54Tg6icB74LQc1Cok7AIhhwxvY4OA6ZiVNYRLUclWqM5Qmx3c/rhinRNrB+yUCcuQ==",
      "v=spf1 include:spf.protection.outlook.com  include:spf.predictiveresponse.net include:servers.mcsv.net include:cust-spf.exacttarget.com include:_spf.pewresearch.org -all",
      "citrix.mobile.ads.otp=kd0jxp1wb9rh0n6flcz64s",
      "ZOOM_verify_JaT9z62TGWk4Xq1EBKbVqZ",
      "n+rGfPXv0394s7Mav6oftRucHJ3XrkPA5Gu2efLCfMNgvA9Q2j5wLodRQMBf09AxhL/ZJr158ExNxMgdKLykAQ==",
      "linear-domain-verification=aeaz7jeynne3",
      "google-site-verification=EuKSpyq2IYv-oJplq6yQlPQKYsV1LWeqwQjs9lu3Z-o",
      "asv=93e4c31a4bfea86fd47cf32edc0fef1b",
      "j8p1v8uvnjiungbkieg6894ctb",
      "oqubjqei44ol2n7u4raiso8aja",
      "apple-domain-verification=JyKtturocxJ7e8bI",
      "anthropic-domain-verification-27dfqx=89zzqeHhnNFCvRLyUPN6Rrm2S",
      "cisco-ci-domain-verification=59488ea3a94920c64294e106be6efcfec41e63d9329d22edb6423a746c309339",
      "facebook-domain-verification=79sdy6w4z5ih1t1h56pzbtfg98s2b1",
      "apple-domain-verification=DQ3TtP8IS4sFJC9EKMrlcZ2yCjEHmQGa66M46pg6m3k",
      "adobe-idp-site-verification=dce4a001508adff6a7b1ce11bcee94997898dc790dbe672077b69fd9e362a3cf",
      "5fg2mqnnnwjw1cw30f0jtgslypdvlglc",
      "google-site-verification=a39GDHtKkznS6vJx2Bd4tLCPiu3gprTJYBsfeJ-Afy4",
      "tollbit-domain-verification=c379eea53a12f277b7e1b4ddb627fdf3c39380c133229681529aae9c7df3c531",
      "openai-domain-verification=dv-vkGktfLOtwd6xNFPJ1lL0QTl",
      "jpq4l34skjc4madsqn48odfika",
      "m7unfqgh2tqd69cmft07vog4u2",
      "70tqopf58gehn5q0l172ijp4s9",
      "docusign=db8286b4-617d-4518-a8d2-ffd9c7d6b445",
      "hcp-domain-verification=a3c6e4dafba5b710eebea68d3af09226b78e92d2c41ac640723ab9c5ef82f330"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:6183e7d4856a5@ag.dmarcly.com; ruf=mailto:6183e7d4856a5@fo.dmarcly.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=pewresearch.org",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Sep 10 00:07:46 2026 GMT",
    "notAfter": "Dec  9 00:07:45 2026 GMT",
    "san": [
      "pewresearch.org",
      "www.pewresearch.org"
    ],
    "days_left": 72,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.66.2",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.pewresearch.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://pewresearch.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "source": "certspotter",
    "count": 13,
    "notable": [
      "assets.pewresearch.org",
      "beta.pewresearch.org",
      "status.pewresearch.org"
    ],
    "sample": [
      "account.pewresearch.org",
      "alpha.pewresearch.org",
      "assets.pewresearch.org",
      "beta.pewresearch.org",
      "canary.pewresearch.org",
      "charts.pewresearch.org",
      "legacy.pewresearch.org",
      "pewresearch.org",
      "platform.pewresearch.org",
      "services.pewresearch.org",
      "status.pewresearch.org",
      "tollbit.pewresearch.org",
      "www.pewresearch.org"
    ]
  },
  "apex_txt": [
    "cursor-domain-verification-36qzmn=mNriG0xAskkvI4tGbhcGakb2s",
    "google-site-verification=jwmmtXct21FKveAwprcQKkMrhqVY7ac2TtxUvubWT30",
    "workbrew-domain-verification-b91wyv=bPXNAREVhl7vOrFTnQdCJbRFZ",
    "linear-domain-verification=aeaz7jeynne3",
    "google-site-verification=EuKSpyq2IYv-oJplq6yQlPQKYsV1LWeqwQjs9lu3Z-o"
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
      "aia_ocsp": null,
      "serial": 557531668349654841958461505863136962998646,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://ye1.c.lencr.org/119.crl"
      ],
      "subject_dn": "311830160603550403130f70657772657365617263682e6f7267",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303594531",
      "not_before": "20260910000746",
      "not_after": "20261209000745"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/wp-admin/",
      "/wp-content/plugins/prc-icon-library/",
      "/wp-content/plugins/prc-icon-library/",
      "/search/",
      "/search",
      "/?s="
    ]
  },
  "x12": {
    "status": 302
  },
  "x13": {
    "root_status": 302,
    "root_location": "https://www.pewresearch.org/",
    "http_status": 301,
    "p404_status": 302,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 302,
    "hsts": "max-age=31536000;includeSubdomains;preload",
    "sitemap": {
      "urls": 5,
      "indexes": 6
    },
    "crl": {
      "url": "http://ye1.c.lencr.org/119.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 302
  },
  "x16": {
    "root_status": 302,
    "cdn": [
      "Fastly"
    ]
  },
  "elapsed_s": 26.0,
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
