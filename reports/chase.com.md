# Security Audit Report — chase.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://chase.com/ |
| Bug bounty program | Chase |
| Listed scope domain | chase.com |
| Test date | 2026-09-27 01:13 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

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
| 12 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 15 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 16 | info | H22 | Server answers with HTTP/1.0 | CWE-319 |
| 17 | info | CT1 | 114 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: BigIP
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
- **Detail:** Header reveals: BigIP
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.chase.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: sinch-domain-verification=6848bb42-da6f-49cf-8974-920af9cf1806; atlassian-domain-verification=wUjrfh2T73RznZOKmEZfc0mRF92bjC7JyjSgRXg9Yt2e9ZMRZw; atlassian-domain-verification=PZApk1vJjd7scChzBMQy2d4NEwk4Bt26obCVACc7vWiOBVCOxT
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on chase.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 15. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The chase.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 16. [INFO] Server answers with HTTP/1.0 (`H22`)

- **CWE:** CWE-319
- **Detail:** The root response of chase.com uses HTTP/1.0, the oldest version still in use; modern sites should serve HTTP/1.1 or 2.
- **Recommendation:** Serve HTTP/1.1 or HTTP/2 from the edge.

### 17. [INFO] 114 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "chase.com",
  "dns": {
    "a": [
      "146.143.13.57",
      "146.143.141.57",
      "146.143.83.57"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "cluster14.us.messagelabs.com (pref 30)",
      "cluster14.us.messagelabs.com (pref 10)",
      "cluster14a.us.messagelabs.com (pref 40)",
      "cluster14.us.messagelabs.com (pref 20)"
    ],
    "ns": [
      "ns0140.secondary.cloudflare.com.",
      "ns1.jpmorganchase.com.",
      "ns06.jpmorganchase.com.",
      "ns05.jpmorganchase.com.",
      "ns0119.secondary.cloudflare.com.",
      "ns2.jpmorganchase.com."
    ],
    "caa": [
      "0 issue \"entrust.net\"",
      "0 issue \"digicert.com\""
    ],
    "spf": [
      "sinch-domain-verification=6848bb42-da6f-49cf-8974-920af9cf1806",
      "atlassian-domain-verification=wUjrfh2T73RznZOKmEZfc0mRF92bjC7JyjSgRXg9Yt2e9ZMRZwafUO6GPJaecYOh",
      "atlassian-domain-verification=PZApk1vJjd7scChzBMQy2d4NEwk4Bt26obCVACc7vWiOBVCOxTOV4/EB9LMexMnl",
      "atlassian-domain-verification=Ua2Fovb97Ak39kxh4koulfhVlpieV1PLhaMkdZpzINDMQGlcvLV+ORgL2QmOryw+",
      "google-site-verification=w00TwyVREI5RpqAT9hqSLZVvZcZi46578G57D1aMGeE",
      "docusign=b04ddbec-21ac-4d6b-bb8b-3f1a3bca079f",
      "wiz-domain-verification=ccd3ec907fff510311f6a14b2a659fcb83adea2818bb6e78503239d2877e8657?",
      "smartsheet-site-validation=JdBS3Kn_332V6dI9U0iq0TV3RZZXTUhL",
      "airtable-verification=1d59ed5062280d21aeef0c14aaf4f950",
      "atlassian-domain-verification\\u003dpD6ozLCGDinP/R+vd5R9hpoPCSOmTFTHfWPK633PXEtELa5KlVDw4w1Pnn02aTdC",
      "wiz-domain-verification=a0d8d067bcb1cdd44255d0633a31df3ba13c82e30f27c080519b0b85ba734d32",
      "_m47rp0d9u3ci4ycif1echp310q0yy09",
      "onetrust-domain-verification=ccee45576c1e4fbfaa4014725a73344f",
      "wiz-domain-verification=66aa74155d5e84d10ed4b5a786a66f94063cff3b4c7e11d09fb46f027736dbf0",
      "pendo-domain-verification=1f6e5677-d405-438e-88ba-141766793ce8",
      "DirectFedAuthUrl=https://idauatg2.jpmorganchase.com/adfs/ls/",
      "google-site-verification=iZwZzo1YPl0G29U136Suzn4c1VptcA_LkvvdWOYC6B0",
      "wiz-domain-verification=68c6d9fa0c4bdd60150d3df50635cd0fcf4af6af079771d90239d10add2c2967",
      "google-site-verification=PfSAyrffyVUKXLc1Ew8C2IFPWkjufFSsbboFz_24Qt4",
      "docusign=500adee6-4cca-451d-bcd8-2813346419c8",
      "v=spf1 include:tpo.chase.com exists:%{i}.spf.chase.com exists:%{i}.spf.hc4673-96.iphmx.com exists:%{i}.spf.hc4698-8.iphmx.com -all"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "jurisdictionCountryName=US, jurisdictionStateOrProvinceName=Delaware, businessCategory=Private Organization, serialNumber=691011, countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=JPMorgan Chase & Co., commonName=www.chase.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert EV RSA CA G2",
    "notBefore": "Sep  8 00:00:00 2026 GMT",
    "notAfter": "Mar 25 23:59:59 2027 GMT",
    "san": [
      "www.chase.com",
      "chase.com",
      "www-ndc.chase.com"
    ],
    "days_left": 179,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "146.143.13.57",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: BigIP"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.chase.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.chase.com/"
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
    "source": "certspotter",
    "count": 114,
    "notable": [],
    "sample": [
      "aemutilities-dev-ecs.chase.com",
      "affluent-jpmpcuat.chase.com",
      "ai-hub.chase.com",
      "ai-nexus-uat.chase.com",
      "ais-jpmc-gateway.chase.com",
      "ams-utilities-test-ecs.chase.com",
      "analytics-web.chase.com",
      "analytics.chase.com",
      "api-mtls-tgs-ext-notifications.chase.com",
      "apix-oauth-qa01.chase.com",
      "apix-oauth-qa02.chase.com",
      "apix-oauth-qa03.chase.com",
      "apix-perf01.chase.com",
      "apix-qa01.chase.com",
      "apix-qa02.chase.com",
      "apix-qa03.chase.com",
      "astonmartinfinancial.chase.com",
      "authe.chase.com",
      "auto-marketplace-dev.chase.com",
      "capture.chase.com"
    ]
  },
  "apex_txt": [
    "sinch-domain-verification=6848bb42-da6f-49cf-8974-920af9cf1806",
    "atlassian-domain-verification=wUjrfh2T73RznZOKmEZfc0mRF92bjC7JyjSgRXg9Yt2e9ZMRZw",
    "atlassian-domain-verification=PZApk1vJjd7scChzBMQy2d4NEwk4Bt26obCVACc7vWiOBVCOxT",
    "atlassian-domain-verification=Ua2Fovb97Ak39kxh4koulfhVlpieV1PLhaMkdZpzINDMQGlcvL",
    "google-site-verification=w00TwyVREI5RpqAT9hqSLZVvZcZi46578G57D1aMGeE"
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
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 10867976606427577069665545680115578464,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertEVRSACAG2.crl",
        "http://crl4.digicert.com/DigiCertEVRSACAG2.crl"
      ],
      "subject_dn": "31133011060b2b0601040182373c0201031302555331193017060b2b0601040182373c020102130844656c6177617265311d301b060355040f0c1450726976617465204f7267616e697a6174696f6e310f300d06035504051306363931303131310b30090603550406130255533111300f060355040813084e657720596f726b3111300f060355040713084e657720596f726b311d301b060355040a0c144a504d6f7267616e204368617365202620436f2e311630140603550403130d7777772e63686173652e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63311e301c06035504031315446967694365727420455620525341204341204732",
      "not_before": "20260908000000",
      "not_after": "20270325235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.chase.com/",
    "http_status": 301,
    "p404_status": 301,
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
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertEVRSACAG2.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "elapsed_s": 54.7,
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
