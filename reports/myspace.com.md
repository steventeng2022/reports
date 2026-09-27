# Security Audit Report — myspace.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://myspace.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | myspace.com |
| Test date | 2026-09-27 01:27 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **33** (High: 0, Medium: 0, Low: 11, Info: 22)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 8 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 9 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 10 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 11 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 12 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 13 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 14 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 15 | info | P8 | Missing security.txt | CWE-1038 |
| 16 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 17 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 18 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 19 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 20 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 21 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 22 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 23 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 24 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 25 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 26 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 27 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 28 | low | HTML5 | State-changing HTML form without an anti-CSRF token | CWE-352 |
| 29 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 30 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 31 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 32 | info | CT1 | 7 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 33 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'persistent_id' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 8. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'persistent_id' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 9. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'visit_id' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 10. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'visit_id' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 11. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'beacons_enabled' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 12. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'beacons_enabled' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 13. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'player' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 14. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'player' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 15. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 16. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 17. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.myspace.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 18. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (r5hfssilcou0x9.myspace.com and q3sqo9h623uln8.myspace.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 19. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=q0iWqpcfOBclAJaCeWh83v62QQ4uCgbWObQ08p37qgU; google-site-verification=eu-3gW1JePvsGRRCaEvH17YUOTFJNofm4lnz2Pk0LTc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 20. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of myspace.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 21. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but myspace.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 22. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 38 disallow path(s), e.g. /settings/*, /manage/*, /signup/*, /thirdpartyimport/*, /insights/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 23. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 34.111.176.156 carries PTR 156.176.111.34.bc.googleusercontent.com. for myspace.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 24. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for myspace.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 25. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on myspace.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of myspace.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 26. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of myspace.com loads 4 cross-origin script(s) without an integrity attribute, e.g. https://cdn.cookielaw.org/consent/ba57dc0e-bed0-43c0-8099-686e40ea64e7-test/OtAutoBlock.js, https://cdn.cookielaw.org/scripttemplates/otSDKStub.js, https://aim.loc.kr/identity-lockr-v1.0.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 27. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on myspace.com lists 13 <loc> URL(s); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 28. [LOW] State-changing HTML form without an anti-CSRF token (`HTML5`)

- **CWE:** CWE-352
- **Detail:** Root document of myspace.com contains 5 state-changing form(s) (POST/PUT/PATCH/DELETE) with no recognizable anti-CSRF token input.
- **Recommendation:** Add a per-session anti-CSRF token to state-changing forms.

### 29. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of myspace.com references 6 distinct third-party registrable domains (e.g. myspacecdn.com, w3.org, cookielaw.org, fouanalytics.com, zendesk.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 30. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of myspace.com sends a CSP but contains 4 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 31. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of myspace.com carries alt-svc h3=":443"; ma=2592000,h3-29=":443"; ma=2592000; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 32. [INFO] 7 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: help.myspace.com, www.help.myspace.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 33. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: www.help.myspace.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "myspace.com",
  "dns": {
    "a": [
      "34.111.176.156"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-00ac0e01.gslb.pphosted.com (pref 10)",
      "mxb-00ac0e01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-cloud-a3.googledomains.com.",
      "ns-cloud-a2.googledomains.com.",
      "ns-cloud-a4.googledomains.com.",
      "ns-cloud-a1.googledomains.com."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=q0iWqpcfOBclAJaCeWh83v62QQ4uCgbWObQ08p37qgU",
      "cr40m536tje9on1slld9bi81bg",
      "al4upe6q5cl13sg4srvfivflvg",
      "qpdYoeakhlmAxsnmxgAVFmJgUSibqb/y+Eu6GGn8pdmLf+mFGIB3jhRAxIC5KObsPMES9MW2c+oOrpOo/lCQVw==",
      "v=spf1 mx ip4:159.183.178.108 ip4:168.245.30.211 ip4:63.208.226.34 ip4:204.16.32.0/22 ip4:67.134.143.0/24 ip4:216.205.243.0/24 ip4:34.85.156.5/32 ip4:35.245.108.108/32 ip4:34.86.129.193/32 ip4:34.86.134.94/32 ",
      "ip4:34.85.222.234/32 ip4:34.86.176.234/32 ip4:34.86.125.212/32 ip4:34.85.224.60/32 ip4:34.86.160.49/32 ip4:35.245.64.166/32 ip4:35.188.226.11/32 ",
      "ip4:34.86.208.228/32 ip4:34.85.216.144/32 ip4:35.221.22.153/32 ip4:34.86.137.108/32 ip4:34.86.51.35/32 ip4:34.150.221.40/32 ip4:34.85.216.70/32 ip4:34.86.37.191/32 ip4:34.85.214.215/32 ",
      "ip4:35.236.234.82/32 ip4:34.86.161.241/32 ip4:216.32.181.16 ip4:216.178.32.0/20 ip4:168.235.224.0/24 include:_netblocks.mimecast.com -all",
      "cj65vjpq0s1v9u7vfo020c6rel",
      "MS=ms89904786",
      "google-site-verification=eu-3gW1JePvsGRRCaEvH17YUOTFJNofm4lnz2Pk0LTc",
      "oZ19a+EOIwWVDPJ7POj14UAGBfzk9xcJMmsTUAMUy7H82sDuVCxvw9rZqdg3znFrdTH04+49zd1djhEAt0ooiA=="
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:postmaster@myspace.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=myspace.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR3",
    "notBefore": "Aug 17 20:48:06 2026 GMT",
    "notAfter": "Nov 15 21:44:01 2026 GMT",
    "san": [
      "myspace.com",
      "*.myspace.com"
    ],
    "days_left": 49,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.111.176.156",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Featured Content on Myspace"
  },
  "mixed_content": [],
  "cookies": [
    {
      "domain": ".myspace.com"
    },
    {
      "domain": ".myspace.com"
    },
    {
      "domain": ".myspace.com"
    },
    {
      "domain": ".myspace.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.myspace.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://myspace.com:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 0,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 200,
    "/api/": 200
  },
  "subdomains": {
    "source": "certspotter",
    "count": 7,
    "notable": [
      "help.myspace.com",
      "www.help.myspace.com"
    ],
    "sample": [
      "ccpa.myspace.com",
      "help.myspace.com",
      "imagedfs.myspace.com",
      "msai-api.myspace.com",
      "msai.myspace.com",
      "myspace.com",
      "www.help.myspace.com"
    ],
    "dangling": [
      "www.help.myspace.com"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=q0iWqpcfOBclAJaCeWh83v62QQ4uCgbWObQ08p37qgU",
    "google-site-verification=eu-3gW1JePvsGRRCaEvH17YUOTFJNofm4lnz2Pk0LTc"
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
      "serial": 5827092271395515619463226872830028792,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/wr3/baFvOwbr8-E.crl"
      ],
      "subject_dn": "311430120603550403130b6d7973706163652e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303575233",
      "not_before": "20260817204806",
      "not_after": "20261115214401"
    }
  },
  "http2": {
    "robots_disallow": [
      "/settings/*",
      "/manage/*",
      "/signup/*",
      "/thirdpartyimport/*",
      "/insights/*",
      "/search/*",
      "/help/*",
      "/auth/*",
      "/library/*",
      "/pages/legal*",
      "/examples/*",
      "/tests/*",
      "/notifications/*",
      "/messages/*",
      "/ajax/*"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "156.176.111.34.bc.googleusercontent.com."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=31536000",
    "sitemap": {
      "urls": 13,
      "indexes": 0
    },
    "crl": {
      "url": "http://c.pki.goog/wr3/baFvOwbr8-E.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "x16": {
    "root_status": 200,
    "alt_svc": "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000"
  },
  "elapsed_s": 41.1,
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
