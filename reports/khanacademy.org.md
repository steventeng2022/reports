# Security Audit Report — khanacademy.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://khanacademy.org/ |
| Bug bounty program | Khan Academy |
| Listed scope domain | khanacademy.org |
| Test date | 2026-09-27 01:25 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 5, Info: 13)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
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
- **Detail:** Header reveals: CloudFront
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

### 14. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (mb99f5ekw41gmu.khanacademy.org and trbwl7imqydz0v.khanacademy.org) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=7kTMmLFa8kfzTFffAv659zZAhSvDX5lqnB_yuST-xLY; stripe-verification=332820F9A5BCCCACBF2F5D8636496EB723C4062C9B878B8BAB77E99A2522; apple-domain-verification=FBF7Yx9o3htFHZ7m
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m01.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 65.9.180.126 carries PTR server-65-9-180-126.tpe53.r.cloudfront.net. for khanacademy.org.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on khanacademy.org identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

## Evidence (raw response observations)

```json
{
  "domain": "khanacademy.org",
  "dns": {
    "a": [
      "65.9.180.126",
      "65.9.180.8",
      "65.9.180.53",
      "65.9.180.111"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "aspmx2.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)"
    ],
    "ns": [
      "ns-125.awsdns-15.com.",
      "ns-1489.awsdns-58.org.",
      "ns-798.awsdns-35.net.",
      "ns-1664.awsdns-16.co.uk."
    ],
    "caa": [
      "0 iodef \"mailto:it@khanacademy.org\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"globalsign.com\"",
      "0 issue \"pki.goog\"",
      "0 issue \"godaddy.com\"",
      "0 issue \"amazon.com\"",
      "0 issue \"digicert.com\"",
      "0 issue \"certainly.com\""
    ],
    "spf": [
      "google-site-verification=7kTMmLFa8kfzTFffAv659zZAhSvDX5lqnB_yuST-xLY",
      "stripe-verification=332820F9A5BCCCACBF2F5D8636496EB723C4062C9B878B8BAB77E99A2522E947",
      "apple-domain-verification=FBF7Yx9o3htFHZ7m",
      "google-site-verification=BUF9CkP4-zm7sN2rDSq6NGRiEkrvvh2k3UdQxwSusrU",
      "v=spf1 include:_spf.google.com include:sendgrid.net include:aspmx.sailthru.com include:mail.zendesk.com exists:%{i}._spf.mta.salesforce.com include:mg-spf.greenhouse.io -all",
      "globalsign-domain-verification=qV_5Us2mt6FO1Ig5hnG4kYHESYAxuH5-qZ0cRXC-Ig",
      "facebook-domain-verification=8kvuco8ljlv8t1aedswjypctrp1pk3",
      "google-site-verification=sHrvDlgokhtbjBWsn8Dhu616EFRRv8GD0C1AU4_1gl4",
      "google-site-verification=y1w1HGdtmQcg92Uy4JtubYkFtDDshCwmDXTFCgjpr-Y",
      "_globalsign-domain-verification=e70UZqvudGByIeilV8oO0gubBZi0P7QLakTxKub-zS",
      "canva-site-verification=JW5MeXNqA7ezvjIRgLOPaQ",
      "cursor-domain-verification-dc9ngn=XEN4zLZD2K4p5yMB2JFUNxGIk",
      "yahoo-verification-key=h5B5VELNOFcyiRDJQWEiNChg+SeClI9Bk9k9daiRPR4=",
      "openai-domain-verification=dv-E4EGw5ZIgYd9B3mwA3dPV5zY",
      "ZOOM_verify_G7FwqtyEKLkoQGhA3ifQq5",
      "cl_verification=a568671a-6112-4bc5-997d-1f06d8389b2e",
      "onetrust-domain-verification=4bc2331ed4d24c81b7be278e6e1fb58b",
      "botify-site-verification=sGRcFNKzIkHzx1jtsQ7YkiT8hgWB6RiU",
      "google-site-verification=JML6gcy7DbE1dA3JB9W4O6EB9uQ8bpOlJTyniVCgd-o",
      "google-site-verification=Jiabx8hC-zV0E8-hAj40dHCY_oWNIvfqkNe7VFnGbCs",
      "_globalsign-domain-verification=Ca9ol7KyPTrPtyGjL1BqGx_wv6SymozDmCXhHJveUr",
      "anthropic-domain-verification-4va7p1=Uuz4j8MkpGFjBjYBqvNGNuK46",
      "hibp-verify=dweb_9nibj6s7woei7t5h43qd3yni",
      "_globalsign-domain-verification=Prrz12gznJzJiHaajX3CnPfpqK6hhLae0miMSZ_BGa",
      "spf2.0/pra include:_spf.google.com include:sendgrid.net include:aspmx.sailthru.com -all",
      "google-site-verification=SprWzGYoIdXdFrUCSyBhXJtHzFjE8FAQNlTamgKenhU",
      "MS=ms10049948"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-reports@khanacademy.org; ruf=mailto:dmarc-reports@khanacademy.org"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=khanacademy.org",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Nov 11 00:00:00 2025 GMT",
    "notAfter": "Dec 10 23:59:59 2026 GMT",
    "san": [
      "khanacademy.org",
      "salkhan.com",
      "www.youcanlearnanything.org",
      "www.conacademy.com",
      "es.pixarinabox.org",
      "www.kahnacademy.com",
      "pt.pixarinabox.com",
      "youcanlearnanything.org",
      "conacademy.com",
      "pixarinabox.com",
      "www.salkhan.com",
      "camp.khankids.org",
      "www.khanacademy.es",
      "conacademy.org",
      "www.pixarinabox.org",
      "kahnacademy.org",
      "www.khankids.org",
      "sendgrid.khanacademy.org",
      "kasandbox.org",
      "www.khanacademy.com",
      "es.pixarinabox.com",
      "khanacademy.com.br",
      "khanacademy.com",
      "khanacademy.es",
      "www.conacademy.org",
      "pt.pixarinabox.org",
      "www.kahnacademy.org",
      "pixarinabox.org",
      "khan.co",
      "khankids.org",
      "www.khankids.com",
      "www.pixarinabox.com",
      "khankids.com",
      "kahnacademy.com",
      "ycla.khanacademy.org"
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
    "ip": "65.9.180.126",
    "open": []
  },
  "https": {
    "status": 308,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.khanacademy.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 308,
    "location": "https://www.khanacademy.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 308",
    "/redirect?next=https://evil-auditor.example/x -> 308",
    "/go?url=https://evil-auditor.example/x -> 308",
    "/url?url=https://evil-auditor.example/x -> 308"
  ],
  "paths": {
    "/robots.txt": 308,
    "/sitemap.xml": 308,
    "/.well-known/security.txt": 308,
    "/security.txt": 308,
    "/.git/HEAD": 308,
    "/.git/config": 308,
    "/.env": 308,
    "/.htaccess": 308,
    "/wp-login.php": 308,
    "/phpmyadmin/index.php": 308,
    "/server-status": 308,
    "/api/": 308
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=7kTMmLFa8kfzTFffAv659zZAhSvDX5lqnB_yuST-xLY",
    "stripe-verification=332820F9A5BCCCACBF2F5D8636496EB723C4062C9B878B8BAB77E99A2522",
    "apple-domain-verification=FBF7Yx9o3htFHZ7m",
    "google-site-verification=BUF9CkP4-zm7sN2rDSq6NGRiEkrvvh2k3UdQxwSusrU",
    "globalsign-domain-verification=qV_5Us2mt6FO1Ig5hnG4kYHESYAxuH5-qZ0cRXC-Ig"
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
      "aia_ocsp": "http://ocsp.r2m01.amazontrust.com",
      "serial": 9356871493532650860346839022262007938,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m01.amazontrust.com/r2m01.crl"
      ],
      "subject_dn": "311830160603550403130f6b68616e61636164656d792e6f7267",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3031",
      "not_before": "20251111000000",
      "not_after": "20261210235959"
    },
    "ocsp": "http-403"
  },
  "x12": {
    "status": 308,
    "ptr": [
      "server-65-9-180-126.tpe53.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 308,
    "root_location": "https://www.khanacademy.org/",
    "http_status": 308,
    "p404_status": 308,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 308,
    "crl": {
      "url": "http://crl.r2m01.amazontrust.com/r2m01.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 308
  },
  "x16": {
    "root_status": 308,
    "cdn": [
      "CloudFront",
      "Fastly"
    ]
  },
  "elapsed_s": 8.1,
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
