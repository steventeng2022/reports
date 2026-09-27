# Security Audit Report — gofundme.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gofundme.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | gofundme.com |
| Test date | 2026-09-27 01:22 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 6, Info: 16)

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
| 10 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 11 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 14 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 19 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 20 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 21 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 22 | info | CT1 | 49 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 10. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'gdid' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 11. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'gdid' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.gofundme.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 14. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (p7yijeft9gk6ue.gofundme.com and ebfyyo5jdx0okb.gofundme.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=O7naSlyLdrJJfCqA4ktOYCn9vrudsbppXY8j0EvSbC0; rippling-domain-verification=40df0889be186979; google-site-verification=cZ9Hawb_wfuisC8fkQbwE1v8bjFJ0cf2bepzKRFDsXQ
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 39 disallow path(s), e.g. /mvc.php*, /*contact?t=donation_page_report, /*campaign/gallery/*, /f/*/widget/*, /f/*/donate/sign-in
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 54.192.248.78 carries PTR server-54-192-248-78.tpe53.r.cloudfront.net. for gofundme.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 19. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for gofundme.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 20. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on gofundme.com lists 51 <loc> URL(s) across 52 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 21. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on gofundme.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 22. [INFO] 49 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api-co.internal.gofundme.com, api-guard.internal.gofundme.com, api.gofundme.com, api.internal.gofundme.com, auth.gofundme.com, docs.gofundme.com, graphql-core.internal.gofundme.com, graphql.internal.gofundme.com, helpdesk.gofundme.com, internal.gofundme.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "gofundme.com",
  "dns": {
    "a": [
      "54.192.248.78",
      "54.192.248.37",
      "54.192.248.43",
      "54.192.248.33"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx5.googlemail.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx3.googlemail.com (pref 30)",
      "aspmx4.googlemail.com (pref 30)"
    ],
    "ns": [
      "ns-1018.awsdns-63.net.",
      "ns-279.awsdns-34.com.",
      "ns-1860.awsdns-40.co.uk.",
      "ns-1148.awsdns-15.org."
    ],
    "caa": [],
    "spf": [
      "ZOOM_verify_uRWfBI2AbJeSqiNLFUItq5",
      "48BCBFD65C",
      "google-site-verification=O7naSlyLdrJJfCqA4ktOYCn9vrudsbppXY8j0EvSbC0",
      "rippling-domain-verification=40df0889be186979",
      "google-site-verification=cZ9Hawb_wfuisC8fkQbwE1v8bjFJ0cf2bepzKRFDsXQ",
      "google-site-verification=qYAWkOCPaLxMmYxSW2YahQ4GG4la3a9hNWFhDJcd2r4",
      "adobe-idp-site-verification=b23a174f3ecb4906444742af94b4c61d1948b6ba9665d33d2127abbac4e4bb6a",
      "facebook-domain-verification=stk03ifpht9yaex2dibsxivrr9yor2",
      "onetrust-domain-verification=ae6ed1d46523448a905b9d8781b1f2d9",
      "globalsign-domain-verification=wvdz6fqNpGYoUxoyCbEUOYrkz-Z8Nh2zXAoS8lsLRh",
      "_globalsign-domain-verification=MK_ZKmss4D_DdzGOsssHxxBOK6hJc6LGycFvNOESdZ",
      "loom-site-verification=2d2eebdbc4004cba854c231b81ddbc37",
      "google-site-verification=3LLkSZCqjHLPPrJiZMqE6AUja9L69F0ogae8o7JU6x4",
      "google-site-verification=1VNhR6mITAZOOgVYtcdutrYdASgKtAnRITXKBQH6N3o",
      "openai-domain-verification=dv-QetyqJL9vMGOTwGXZe04zDzf",
      "D24pYKS_dVZOjQrnXT0sZd8wICnikg",
      "docusign=852fdcf3-d757-4993-acd7-50a6a836365f",
      "maestro-cloud-domain-verification-8sf8ap=UAP61AxkIXLrtLqM3DPIjAOP3",
      "linear-domain-verification=fdr7mty4ieug",
      "canva-site-verification=IqTb0UBeilINf10w5raSTQ",
      "docker-verification=f1a95df7-225d-4b44-a5d5-852c4e55539f",
      "google-site-verification=MyZCdkOIehJ00yJgtChbK4geHjxlUnuSGXwBI4n73xs",
      "google-site-verification=PVGZ_SowsyCYImkZyR7BWQAf0xBoWeUIuQ-9zwwio2s",
      "google-site-verification=-97-MskUtq0BKfJ4HGBHfGDbU2XBfza9wf9pUk_3aWs",
      "google-site-verification=lWd6YulLrAH6-0uZ5AX-P5-VcxTnfjF2aQ9Ey7lK96o",
      "apple-domain-verification=VWhGR6I4xDAzdl50",
      "MS=ms75016599",
      "onetrust-domain-verification=6311c78fff614a938475a7085108477b",
      "google-site-verification=yTucH5oN_CeaxxpMntyk_jYQMtGyAv8W6rPZjHdXwIA",
      "google-site-verification=NtmRkQwVZHP-qs02vSRFkLA3Wn8xmi93HEEJsIpQaWU",
      "atlassian-domain-verification=pDoSyXtzAVxSEb/lQ90Pfrgh87LFeL3vh9cAmjYGXaONtLKtJzDxfD2ARw8sqn/i",
      "gamma-domain-verification-g2tf71=XUfSVhJFiN82HacNFl6iLBfvZ",
      "zapier-domain-verification-challenge=822070a7-9aa6-45fc-a3fa-d67b2dbc6c23",
      "google-site-verification=J5wipyL1r3azHeawGlORXWlBscqyoYTcQpvlSeldLdQ",
      "google-site-verification=9J3ulCSuevKr0hSdxoSmyccnjKgO1Qk_h55qjGJWMdk",
      "hubspot-domain-verification=OWZlYTIzYmQtNjhlMi00MmU4LWI0NWEtYjE4NGM2MDFiZjdl",
      "google-site-verification=Lj3x8aEMLy8y3btjGcK48UpZsOJobv1zIFdK6lDzLMY",
      "_wpengine-sso-challenge=3Bj5M7GKohpXqt6K7ufz30hQAMH",
      "mgverify=fdcb133238019c86b951dbb58430f60163ad2967fa91a367a65ea9a4edcf538e",
      "v=spf1 include:gofundme.com._nspf.vali.email  include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:mail.zendesk.com include:servers.mcsv.net include:emailus.freshservice.com include:docebosaas.com include:sparkpostmail.com ~all",
      "google-site-verification=uvhS3R59UN5exwoSVEi9oFgrQtcrDlWYQMcWRVe5S68",
      "anthropic-domain-verification-t4e4qe=Q1VWFhuqdtNXUmkvbvPe0aNCH",
      "knqas9grs1e90id70n6qtblc6s",
      "stripe-verification=7e70d91b569f8a0590a7b1b4c2933dade452811dee08d86cfce9ea1db35bff14",
      "twilio-domain-verification=0fbe678874c1832be4b21e661c491ee6",
      "pinterest-site-verification=b367ddd575e4643b2ac5fefbb3bf84c6"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@vali.email,mailto:sre+valiagg@gofundme.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.gofundme.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jul 26 00:00:00 2026 GMT",
    "notAfter": "Feb  8 23:59:59 2027 GMT",
    "san": [
      "*.gofundme.com",
      "gofundme.com"
    ],
    "days_left": 134,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.78",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [
    {
      "domain": "gofundme.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.gofundme.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://gofundme.com:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 502,
    "/.htaccess": 502,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 49,
    "notable": [
      "api-co.internal.gofundme.com",
      "api-guard.internal.gofundme.com",
      "api.gofundme.com",
      "api.internal.gofundme.com",
      "auth.gofundme.com",
      "docs.gofundme.com",
      "graphql-core.internal.gofundme.com",
      "graphql.internal.gofundme.com",
      "helpdesk.gofundme.com",
      "internal.gofundme.com",
      "partner-api.internal.gofundme.com",
      "status.gofundme.com",
      "support.gofundme.com",
      "vanilla.sso.gofundme.com",
      "www.vanilla.sso.gofundme.com"
    ],
    "sample": [
      "ablink.marketing.gofundme.com",
      "ablink.messages.gofundme.com",
      "api-co.internal.gofundme.com",
      "api-guard.internal.gofundme.com",
      "api.gofundme.com",
      "api.internal.gofundme.com",
      "app1-api.gofundme.com",
      "app2-api.gofundme.com",
      "auth.gofundme.com",
      "charitydocs.gofundme.com",
      "discoverpro.gofundme.com",
      "docs.gofundme.com",
      "email.prosend.gofundme.com",
      "gateway.gofundme.com",
      "go.gofundme.com",
      "gofundme.com",
      "graphql-core.internal.gofundme.com",
      "graphql.internal.gofundme.com",
      "happiness.gofundme.com",
      "helpdesk.gofundme.com"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=O7naSlyLdrJJfCqA4ktOYCn9vrudsbppXY8j0EvSbC0",
    "rippling-domain-verification=40df0889be186979",
    "google-site-verification=cZ9Hawb_wfuisC8fkQbwE1v8bjFJ0cf2bepzKRFDsXQ",
    "google-site-verification=qYAWkOCPaLxMmYxSW2YahQ4GG4la3a9hNWFhDJcd2r4",
    "adobe-idp-site-verification=b23a174f3ecb4906444742af94b4c61d1948b6ba9665d33d2127"
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
      "aia_ocsp": "http://ocsp.r2m04.amazontrust.com",
      "serial": 13893156052134787556876830562696313335,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "subject_dn": "3117301506035504030c0e2a2e676f66756e646d652e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20260726000000",
      "not_after": "20270208235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/mvc.php*",
      "/*contact?t=donation_page_report",
      "/*campaign/gallery/*",
      "/f/*/widget/*",
      "/f/*/donate/sign-in",
      "/track",
      "/track/exposure",
      "/auth",
      "/f/*/fb/*",
      "/f/*/x/*",
      "/f/*/ig/*",
      "/f/*/wa/*",
      "/f/*/li/*",
      "/f/*/e/*",
      "/f/*/sms/*"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "server-54-192-248-78.tpe53.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.gofundme.com/",
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
    "hsts": "max-age=31536000; includeSubDomains; preload",
    "sitemap": {
      "urls": 51,
      "indexes": 52
    },
    "crl": {
      "url": "http://crl.r2m04.amazontrust.com/r2m04.crl",
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
      "CloudFront",
      "Fastly"
    ]
  },
  "elapsed_s": 22.3,
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
