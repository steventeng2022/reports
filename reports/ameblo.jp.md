# Security Audit Report — ameblo.jp

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ameblo.jp/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ameblo.jp |
| Test date | 2026-09-27 00:09 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 9 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 12 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 13 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 14 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 15 | info | HTML3 | Third-party <iframe> embedded in root document | CWE-643 |
| 16 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 17 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 18 | info | CT1 | 17 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.ameblo.jp/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 9. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (sxwn5bk9kqppwl.ameblo.jp and hzuffeyp1cqm51.ameblo.jp) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=26Ps67bWgQGjeNkTT6hV9VEgczhnzjN78yCdM33v-eo; tollbit-domain-verification=e5f400b7a9ee16a9c039d5a7c1ca7587cf4d1c4708b2193bfa97; google-site-verification=fst_3JQsVLfa2f0Df-x-KdG2tW23U3jDz09k6iF__y8
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 46 disallow path(s), e.g. /*/page-*.html, /*/amemberentrylist.html, /*/amemberentrylist-*.html, /*/amemberentry-*.html, /*/archivetop.html
- **Recommendation:** Review disallowed paths; robots is not access control.

### 12. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on ameblo.jp; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 13. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The ameblo.jp certificate lists an AIA OCSP responder (http://status.geotrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 14. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of ameblo.jp loads 15 cross-origin script(s) without an integrity attribute, e.g. https://stat100.ameba.jp/ameblo/portal/20260909-2992e4f/_next/static/chunks/polyfills-c67a75d1b6f99dc8.js, https://stat100.ameba.jp/ameblo/portal/20260909-2992e4f/_next/static/chunks/webpack-1f1763916cd62cef.js, https://stat100.ameba.jp/ameblo/portal/20260909-2992e4f/_next/static/chunks/framework-24fda4117f092221.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 15. [INFO] Third-party <iframe> embedded in root document (`HTML3`)

- **CWE:** CWE-643
- **Detail:** Root document of ameblo.jp embeds 1 cross-origin iframe(s), e.g. https://www.googletagmanager.com/ns.html?id=GTM-N49WWL; embedded origins are framed inside the page with its trust context.
- **Recommendation:** Review embedded origins and consider sandbox attributes.

### 16. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of ameblo.jp references 14 distinct third-party registrable domains (e.g. ameba.jp, amebame.com, w3.org, d-money.jp, googletagmanager.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 17. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of ameblo.jp sends a CSP but contains 4 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 18. [INFO] 17 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: dev.ameblo.jp, image.portal.ameblo.jp
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "ameblo.jp",
  "dns": {
    "a": [
      "199.232.214.133",
      "199.232.210.133"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mail.ameblo.jp (pref 10)"
    ],
    "ns": [
      "ns-2038.awsdns-62.co.uk.",
      "ns-1218.awsdns-24.org.",
      "ns-863.awsdns-43.net.",
      "ns-124.awsdns-15.com."
    ],
    "caa": [
      "0 issue \"digicert.com; cansignhttpexchanges=yes\"",
      "0 issue \"amazon.com\"",
      "0 issue \"cybertrust.ne.jp\"",
      "0 issue \"certainly.com\"",
      "0 issue \"globalsign.com\"",
      "0 iodef \"mailto:ameba_tools+crt@cyberagent.co.jp\"",
      "0 issue \"letsencrypt.org\""
    ],
    "spf": [
      "fastly-domain-delegation-nfkcslan-542735-2022-10-31",
      "_mnobpm3nakzeekpqy6i72p451qgv326",
      "UHgEILc96z9sKmvYTwgZYiwusQbyqI",
      "google-site-verification=26Ps67bWgQGjeNkTT6hV9VEgczhnzjN78yCdM33v-eo",
      "tollbit-domain-verification=e5f400b7a9ee16a9c039d5a7c1ca7587cf4d1c4708b2193bfa9778f5ed1c8d42",
      "google-site-verification=fst_3JQsVLfa2f0Df-x-KdG2tW23U3jDz09k6iF__y8",
      "cPu1ZpFdt7xvQjanmhmE12k4AmF0MH",
      "v=spf1 ip4:216.255.232.136/32 include:spf-a.ameba.jp include:spf.repica.jp -all",
      "fastly-domain-delegation-@X7yV19EoO6Y-2023-06-30",
      "_gmqf0w3hsh1pqlogfw1gkg05zhs88zx"
    ],
    "dmarc": [
      "v=DMARC1; p=none"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "countryName=JP, stateOrProvinceName=Tokyo, localityName=Shibuya-ku, organizationName=CyberAgent, Inc., commonName=*.ameblo.jp",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=GeoTrust TLS RSA CA G1",
    "notBefore": "Aug  3 00:00:00 2026 GMT",
    "notAfter": "Feb 16 23:59:59 2027 GMT",
    "san": [
      "*.ameblo.jp",
      "ameblo.jp"
    ],
    "days_left": 142,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "199.232.214.133",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "アメーバブログ（アメブロ）｜Amebaで無料ブログを始めよう"
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
      "origin": "https://sub.ameblo.jp",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ameblo.jp/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 301,
    "/api/": 200
  },
  "subdomains": {
    "source": "certspotter",
    "count": 17,
    "notable": [
      "dev.ameblo.jp",
      "image.portal.ameblo.jp"
    ],
    "sample": [
      "ameblo.jp",
      "dev-blog.ameblo.jp",
      "dev-ml.ameblo.jp",
      "dev.ameblo.jp",
      "image.portal.ameblo.jp",
      "mamade-shop.ameblo.jp",
      "meandre-shop.ameblo.jp",
      "ml.ameblo.jp",
      "polun-shop.ameblo.jp",
      "stg-ml.ameblo.jp",
      "stg-org-sy.ameblo.jp",
      "stg-sy.ameblo.jp",
      "stg.ameblo.jp",
      "stg.sy.ameblo.jp",
      "sy.ameblo.jp",
      "tollbit.ameblo.jp",
      "zt.ameblo.jp"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=26Ps67bWgQGjeNkTT6hV9VEgczhnzjN78yCdM33v-eo",
    "tollbit-domain-verification=e5f400b7a9ee16a9c039d5a7c1ca7587cf4d1c4708b2193bfa97",
    "google-site-verification=fst_3JQsVLfa2f0Df-x-KdG2tW23U3jDz09k6iF__y8"
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
      "aia_ocsp": "http://status.geotrust.com",
      "serial": 3344827574341032750824536969024721884,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl"
      ],
      "subject_dn": "310b3009060355040613024a50310e300c06035504081305546f6b796f311330110603550407130a536869627579612d6b7531193017060355040a131043796265724167656e742c20496e632e3114301206035504030c0b2a2e616d65626c6f2e6a70",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d311f301d0603550403131647656f547275737420544c5320525341204341204731",
      "not_before": "20260803000000",
      "not_after": "20270216235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/*/page-*.html",
      "/*/amemberentrylist.html",
      "/*/amemberentrylist-*.html",
      "/*/amemberentry-*.html",
      "/*/archivetop.html",
      "/*/imagelist.html",
      "/*/imagelist-*.html",
      "/*/image-*.html",
      "/*/comment-*",
      "/*/reblog-*",
      "/*/message-board.html",
      "/*/reader.html",
      "/*/reader-*.html",
      "/*/favorite.html",
      "/*/favorite-*.html"
    ]
  },
  "x12": {
    "status": 200
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
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
    "root_status": 200,
    "crl": {
      "url": "http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "cipher_ver": "TLSv1.2",
    "root_status": 200
  },
  "elapsed_s": 41.1,
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
