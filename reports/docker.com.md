# Security Audit Report — docker.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://docker.com/ |
| Bug bounty program | Docker |
| Listed scope domain | docker.com |
| Test date | 2026-09-27 02:25 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 4, Info: 15)

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
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 18 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 19 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Pantheon
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
- **Detail:** Header reveals: Pantheon
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
- **Detail:** Apex TXT records with verification/token content: sonatype-domain-verification=OSSRH-62474; google-site-verification=5e33xBJIwW1XU49IqmIYtN7yi2Iq0GNnWwN4ujn4G_M; zapier-domain-verification-challenge=c3e7ddaf-20bf-40ca-9374-1a917b16be06
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of docker.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 24 disallow path(s), e.g. /wp-admin/, /pricing/contact-sales/bss-cc-thankyou/, /pricing/contact-sales/bss-thankyou/, /company/contact-thank-you/, /thank-you-subscribing-docker-weekly/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on docker.com lists 15 <loc> URL(s) across 16 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 18. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on docker.com identify the edge as Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 19. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of docker.com discloses a 1-hop fronting chain (1.1 varnish); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

## Evidence (raw response observations)

```json
{
  "domain": "docker.com",
  "dns": {
    "a": [
      "23.185.0.4"
    ],
    "aaaa": [
      "2620:12a:8000::4",
      "2620:12a:8001::4"
    ],
    "cname": null,
    "mx": [
      "alt3.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-1289.awsdns-33.org.",
      "ns-207.awsdns-25.com.",
      "ns-568.awsdns-07.net.",
      "ns-1981.awsdns-55.co.uk."
    ],
    "caa": [
      "0 issue \"sectigo.com\"",
      "0 issue \"amazon.com\"",
      "0 issue \"pki.goog\"",
      "0 issue \"digicert.com\"",
      "0 issue \"comodoca.com\"",
      "0 iodef \"mailto:infra+caa-iodef@docker.com\"",
      "0 issue \"letsencrypt.org\""
    ],
    "spf": [
      "sonatype-domain-verification=OSSRH-62474",
      "google-site-verification=5e33xBJIwW1XU49IqmIYtN7yi2Iq0GNnWwN4ujn4G_M",
      "zapier-domain-verification-challenge=c3e7ddaf-20bf-40ca-9374-1a917b16be06",
      "google-site-verification=CFmV0geNs1hCxK0mBEpjWaDoNwBIiDxIRjTvt3YGRDM",
      "MS=ms98031138",
      "google-site-verification=VbuWA5NflxQMko2x9BJFIPVYrbuxHQll4UP4gZ4Fm08",
      "google-site-verification=rCKOZlVmB_xuu9DiT-urSmmXAEUGn5RI8PxdyCW5LJg",
      "cursor-domain-verification-pkwbtp=KD6kIrkeudCadzeviiVJgEWnd",
      "anthropic-domain-verification-p1ks1q=BmUzJzzDzqNXVWLXmZVoEvTr3",
      "miro-verification=116f0987438eb5a48c070e080a68e7d7b3087e5f",
      "google-site-verification=GjEZ_3KyjpDbmRzGdMUtqMeuXdh7HCSc8uRsPGYL-I0",
      "jamf-site-verification=jqNgc5MzMp4UnSANweyyEQ",
      "airtable-verification=7f122efe7db6b16848108e469042c39c",
      "opine-verification=14d8ea53-d8ae-406f-93b0-76dc879d9b46",
      "apple-domain-verification=S580UenDqcwy2I1X",
      "docusign=aeb25cd4-f743-4efc-b6fb-b8bc5dd1d0e8",
      "docker-verification=4b72827b-32c1-4fe6-a843-2256c0df8a31",
      "astro-domain-verification=cljrj1fgz00hm01lvtaq65gnn",
      "adobe-idp-site-verification=a8d1a71d0cba44c2521bcb451d9dc708ee20d93c7b5b04791f699d128bbe6ec2",
      "atlassian-domain-verification=I1f5bgOm9sPUEcK/2JTD6weNlWt+Wwsyo5dwvJe1fGjf9V+x3kyqxZRrl9z7ILEK",
      "v=spf1 include:_spf.google.com include:spf.tipalti.com include:_spf.salesforce.com include:mktomail.com include:mail.zendesk.com -all",
      "sinch-domain-verification=d8a66194-44cf-49c3-96ab-74325ad6e7be",
      "d0vcwvtyam",
      "openai-domain-verification=dv-tj9VEsgExQvdNl9SCOa2Awju",
      "detectify-verification=87a64c3bf3301354588d90672bd1b74e",
      "google-site-verification=Nyiwo5q4kkaD5V-sEiXsW74HXyVRtKVyxYFfZuFLG7M",
      "MS=ms42223923",
      "google-site-verification=i6hYWAXRYCtHNnyiQAYXiy_4StkAMJQiNCfH-3olY-I",
      "onetrust-domain-verification=fb12882ae6344670a7b91077bd57c0f1",
      "google-site-verification=4PyKLfy_lowkc_qcu-byUkmF1kxAUT7tfho7ZiP353s",
      "stripe-verification=804359af3a919b4a46343227e384abdf33e10ad5bb81ea9f1d17ed4e74486ab4"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=100; rua=mailto:q1xwnepx@ag.dmarcian.com; ruf=mailto:q1xwnepx@fr.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=docker.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Jul 30 10:32:24 2026 GMT",
    "notAfter": "Oct 28 10:32:23 2026 GMT",
    "san": [
      "docker.com",
      "www.docker.com"
    ],
    "days_left": 31,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.185.0.4",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Pantheon"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.docker.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.docker.com/"
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
    "sonatype-domain-verification=OSSRH-62474",
    "google-site-verification=5e33xBJIwW1XU49IqmIYtN7yi2Iq0GNnWwN4ujn4G_M",
    "zapier-domain-verification-challenge=c3e7ddaf-20bf-40ca-9374-1a917b16be06",
    "google-site-verification=CFmV0geNs1hCxK0mBEpjWaDoNwBIiDxIRjTvt3YGRDM",
    "google-site-verification=VbuWA5NflxQMko2x9BJFIPVYrbuxHQll4UP4gZ4Fm08"
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
      "serial": 580775702581867877342694108826174536527601,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://yr1.c.lencr.org/114.crl"
      ],
      "san": [
        "docker.com",
        "www.docker.com"
      ],
      "subject_dn": "311330110603550403130a646f636b65722e636f6d",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303595231",
      "not_before": "20260730103224",
      "not_after": "20261028103223"
    }
  },
  "http2": {
    "robots_disallow": [
      "/wp-admin/",
      "/pricing/contact-sales/bss-cc-thankyou/",
      "/pricing/contact-sales/bss-thankyou/",
      "/company/contact-thank-you/",
      "/thank-you-subscribing-docker-weekly/",
      "/pricing/contact-sales2/",
      "/cdn-cgi/",
      "/static/",
      "/c/",
      "/p/",
      "/products/telepresence-for-docker/thank-you/",
      "/style-guide/",
      "/search/",
      "/ja-jp/wp-admin/",
      "/ja-jp/pricing/contact-sales/bss-cc-thankyou/"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.docker.com/",
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
    "sitemap": {
      "urls": 15,
      "indexes": 16
    },
    "crl": {
      "url": "http://yr1.c.lencr.org/114.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "cdn": [
      "Fastly"
    ]
  },
  "x17": {
    "via": "1.1 varnish"
  },
  "elapsed_s": 35.4,
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
