# Security Audit Report — opera.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://opera.com/ |
| Bug bounty program | Opera Public Bug Bounty |
| Listed scope domain | opera.com |
| Test date | 2026-09-26 22:12 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 3, Info: 12)

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
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 15 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |

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

### 10. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 11. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=zsu8s2znTOAuZ0dkksfMdQE3HmkoNNyuijNib1xkiQo; facebook-domain-verification=up2ljn0zco95f4f16hjxe6we815q19; google-site-verification=M1WsVfJ0xUplsAdeDZ76BkHn9QL-IOWDyq9zziApgAI
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but opera.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 34 disallow path(s), e.g. /o/, /*/o/, /abtest/, /*/abtest/, /api/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 185.26.182.103 carries PTR opera.com. for opera.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 15. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The opera.com certificate lists an AIA OCSP responder (http://statusd.digitalcertvalidation.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

## Evidence (raw response observations)

```json
{
  "domain": "opera.com",
  "dns": {
    "a": [
      "185.26.182.103",
      "185.26.182.104"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "ALT3.ASPMX.L.GOOGLE.com (pref 10)",
      "ASPMX.L.GOOGLE.com (pref 1)",
      "ALT1.ASPMX.L.GOOGLE.com (pref 5)",
      "ALT4.ASPMX.L.GOOGLE.com (pref 10)",
      "ALT2.ASPMX.L.GOOGLE.com (pref 5)"
    ],
    "ns": [
      "nic6.opera.com.",
      "nic3.opera.com.",
      "nic4.opera.com.",
      "nic2.opera.com.",
      "nic1.opera.com."
    ],
    "caa": [
      "0 iodef \"mailto:hostmaster@opera.com\"",
      "0 issue \"globalsign.com\"",
      "0 issue \"digicert.com\"",
      "0 issue \"sectigo.com\"",
      "0 issue \"trust-provider.com\""
    ],
    "spf": [
      "google-site-verification=zsu8s2znTOAuZ0dkksfMdQE3HmkoNNyuijNib1xkiQo",
      "baaff065e3b7dbc102b34ce11a472f5c",
      "FIO7ppPA1vjosCuWmpg32zcajEQgpx5RgsHG78x2T5oojZ2C6ujnN",
      "facebook-domain-verification=up2ljn0zco95f4f16hjxe6we815q19",
      "google-site-verification=M1WsVfJ0xUplsAdeDZ76BkHn9QL-IOWDyq9zziApgAI",
      "07b121f99e9843a192c18b3cf340b8fb",
      "adobe-idp-site-verification=61e18c604ee93df7fb52b11bab48531b3112c62f0db7249f99463fa327f9c69d",
      "apple-domain-verification=SWfwiYtREsASOqwv",
      "_nt0mk4rbdlrkccjcxafujsak0umpiu7",
      "keybase-site-verification=uH1gfE9c0VONYIy9Hq-WuhCOx6JclPV3_M3j9fAPnXU",
      "google-site-verification=mi7mVeHWYoxrnV4M85YytexDvFMwa23tvOOcg0f0w-E",
      "BQ33d38Z4c0YY0OBRQuXcXsgWcVd9_w",
      "teamtailor=baaff065e3b7dbc102b34ce11a472f5c",
      "v=spf1 ip4:185.26.182.76 ip4:195.189.142.89 ip6:2001:4c28:4000:722:185:26:182:76 ip6:2001:4c28:4000:779:195:189:142:89 mx include:_spf.google.com ~all",
      "openai-domain-verification=dv-kjAJTFRCoOY6YboxYHmIN5wi"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; aspf=s; adkim=s; ri=86400; rua=mailto:c22187dc@in.mailhardener.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.opera.com",
    "issuer": "countryName=NL, organizationName=Trust Provider B.V., organizationalUnitName=Domain Validated SSL, commonName=Trust Provider B.V. TLS RSA CA G1",
    "notBefore": "Jan  7 00:00:00 2026 GMT",
    "notAfter": "Feb  6 23:59:59 2027 GMT",
    "san": [
      "*.opera.com",
      "opera.com"
    ],
    "days_left": 133,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "185.26.182.103",
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
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.opera.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://opera.com/"
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
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=zsu8s2znTOAuZ0dkksfMdQE3HmkoNNyuijNib1xkiQo",
    "facebook-domain-verification=up2ljn0zco95f4f16hjxe6we815q19",
    "google-site-verification=M1WsVfJ0xUplsAdeDZ76BkHn9QL-IOWDyq9zziApgAI",
    "adobe-idp-site-verification=61e18c604ee93df7fb52b11bab48531b3112c62f0db7249f9946",
    "apple-domain-verification=SWfwiYtREsASOqwv"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": "http://statusd.digitalcertvalidation.com",
      "not_before": "20260107000000",
      "not_after": "20270206235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/o/",
      "/*/o/",
      "/abtest/",
      "/*/abtest/",
      "/api/",
      "/client/",
      "/downloadassets/",
      "/*/downloadassets/",
      "/download/get*",
      "/get$",
      "/get/",
      "/promoassets/",
      "/*/promoassets/",
      "/campaign/",
      "/*/campaign/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "opera.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.opera.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 34.5,
  "rechecked": "2026-09-26 21:56 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- Findings are reported against the public program scope; submission through the program tracker is pending.
