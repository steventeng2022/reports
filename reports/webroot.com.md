# Security Audit Report — webroot.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://webroot.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | webroot.com |
| Test date | 2026-09-27 01:37 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **46** (High: 0, Medium: 6, Low: 12, Info: 28)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 4 | medium | PRT21 | FTP service (cleartext) reachable | CWE-319 |
| 5 | info | PRT25 | SMTP (port 25) reachable | CWE-200 |
| 6 | info | PRT53 | DNS service reachable | CWE-200 |
| 7 | info | PRT110 | POP3 (cleartext) reachable | CWE-319 |
| 8 | info | PRT143 | IMAP (cleartext) reachable | CWE-319 |
| 9 | info | PRT993 | IMAPS (port 993) reachable | CWE-200 |
| 10 | info | PRT995 | POP3S (port 995) reachable | CWE-200 |
| 11 | medium | PRT1433 | MSSQL (port 1433) reachable | CWE-200 |
| 12 | medium | PRT3306 | MySQL (port 3306) reachable | CWE-200 |
| 13 | info | PRT3389 | RDP (port 3389) reachable | CWE-200 |
| 14 | medium | PRT5900 | VNC (port 5900) reachable | CWE-200 |
| 15 | medium | PRT6379 | Redis (port 6379) reachable | CWE-200 |
| 16 | info | PRT8000 | Alternate web service (port 8000) reachable | CWE-200 |
| 17 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 18 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 19 | info | PRT8888 | Alternate web service (port 8888) reachable | CWE-200 |
| 20 | info | PRT9090 | Service (port 9090, e.g. Elasticsearch/debug) reachable | CWE-200 |
| 21 | medium | PRT9200 | Elasticsearch (port 9200) reachable | CWE-200 |
| 22 | info | TECH1 | Technology fingerprint | CWE-200 |
| 23 | low | H2 | Missing CSP header | CWE-1021 |
| 24 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 25 | low | H4 | No clickjacking protection | CWE-1023 |
| 26 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 27 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 28 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 29 | info | H6 | Server technology disclosure | CWE-200 |
| 30 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 31 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 32 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 33 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 34 | info | P8 | Missing security.txt | CWE-1038 |
| 35 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 36 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 37 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 38 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 39 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 40 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 41 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 42 | low | CK6 | Session-like cookie lacks both Secure and SameSite | CWE-614 |
| 43 | low | CK8 | Session-like cookie with >=30-day lifetime | CWE-613 |
| 44 | low | CK8 | Session-like cookie with >=30-day lifetime | CWE-613 |
| 45 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 46 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 15 days (notAfter Oct 12 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 4. [MEDIUM] FTP service (cleartext) reachable (`PRT21`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 45.60.151.109:21 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] SMTP (port 25) reachable (`PRT25`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:25 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 6. [INFO] DNS service reachable (`PRT53`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:53 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 7. [INFO] POP3 (cleartext) reachable (`PRT110`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 45.60.151.109:110 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 8. [INFO] IMAP (cleartext) reachable (`PRT143`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 45.60.151.109:143 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 9. [INFO] IMAPS (port 993) reachable (`PRT993`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:993 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 10. [INFO] POP3S (port 995) reachable (`PRT995`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:995 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 11. [MEDIUM] MSSQL (port 1433) reachable (`PRT1433`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:1433 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 12. [MEDIUM] MySQL (port 3306) reachable (`PRT3306`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:3306 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 13. [INFO] RDP (port 3389) reachable (`PRT3389`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:3389 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 14. [MEDIUM] VNC (port 5900) reachable (`PRT5900`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:5900 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 15. [MEDIUM] Redis (port 6379) reachable (`PRT6379`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:6379 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 16. [INFO] Alternate web service (port 8000) reachable (`PRT8000`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:8000 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 17. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 18. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 19. [INFO] Alternate web service (port 8888) reachable (`PRT8888`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:8888 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 20. [INFO] Service (port 9090, e.g. Elasticsearch/debug) reachable (`PRT9090`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:9090 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 21. [MEDIUM] Elasticsearch (port 9200) reachable (`PRT9200`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 45.60.151.109:9200 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 22. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Vercel
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 23. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 24. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 25. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 26. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 27. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 28. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 29. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Vercel
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 30. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'visid_incap_3211517' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 31. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'visid_incap_3211517' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 32. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'incap_ses_176_3211517' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 33. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'incap_ses_176_3211517' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 34. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 35. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 36. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): stspg-custo (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 37. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 38. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 39. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=W342u9ABN8CsWzHJEUTnnprvsso64lGHcBzHIjXtP4A; status-page-domain-verification=2tbgnrpnfp6b; status-page-domain-verification=ry2yxtvp8dt4
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 40. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but webroot.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 41. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 23 disallow path(s), e.g. /*?trpd=*, /*?loc=*, /*?WRSID=*, /*?lang=*, /au/en/cart
- **Recommendation:** Review disallowed paths; robots is not access control.

### 42. [LOW] Session-like cookie lacks both Secure and SameSite (`CK6`)

- **CWE:** CWE-614
- **Detail:** Cookie 'visid_incap_3211517' set on webroot.com has neither the Secure nor the SameSite attribute: interception exposure plus un-gated CSRF usability.
- **Recommendation:** Set Secure and SameSite=Lax (or Strict) on session-like cookies.

### 43. [LOW] Session-like cookie with >=30-day lifetime (`CK8`)

- **CWE:** CWE-613
- **Detail:** Cookie 'SSID' on webroot.com is session-like but carries a Max-Age/Expires lifetime of 30 days or more; a stolen cookie stays valid for a long window.
- **Recommendation:** Shorten session-cookie lifetime and/or require re-authentication for sensitive actions.

### 44. [LOW] Session-like cookie with >=30-day lifetime (`CK8`)

- **CWE:** CWE-613
- **Detail:** Cookie 'visid_incap_3211517' on webroot.com is session-like but carries a Max-Age/Expires lifetime of 30 days or more; a stolen cookie stays valid for a long window.
- **Recommendation:** Shorten session-cookie lifetime and/or require re-authentication for sensitive actions.

### 45. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on webroot.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of webroot.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 46. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on webroot.com lists 192 <loc> URL(s); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

## Evidence (raw response observations)

```json
{
  "domain": "webroot.com",
  "dns": {
    "a": [
      "45.60.151.109",
      "45.60.171.109"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-00102601.gslb.pphosted.com (pref 1)",
      "mxb-00102601.gslb.pphosted.com (pref 1)"
    ],
    "ns": [
      "dns1.safenames.com.",
      "dns3.safenames.org.",
      "dns2.safenames.net."
    ],
    "caa": [
      "0 issue \"letsencrypt.org\"",
      "0 issue \"amazon.com\"",
      "0 issuewild \"amazontrust.com\"",
      "0 issuewild \"awstrust.com\"",
      "0 issuewild \"sectigo.com\"",
      "0 issuewild \"letsencrypt.org\"",
      "0 issue \"awstrust.com\"",
      "0 issue \"sectigo.com\"",
      "0 issuewild \"digicert.com\"",
      "0 issuewild \"amazon.com\"",
      "0 issue \"digicert.com\"",
      "0 issue \"amazontrust.com\"",
      "0 issuewild \"amazonaws.com\"",
      "0 issue \"amazonaws.com\""
    ],
    "spf": [
      "google-site-verification=W342u9ABN8CsWzHJEUTnnprvsso64lGHcBzHIjXtP4A",
      "status-page-domain-verification=2tbgnrpnfp6b",
      "status-page-domain-verification=ry2yxtvp8dt4",
      "v=spf1 ip4:66.35.53.240 ip4:66.35.53.180 ip4:208.87.139.150 ip4:66.35.53.248 ip4:208.74.204.0/22 ip4:46.19.168.0/23 ip4:208.87.139.64 ip4:208.87.139.66 include:spf.protection.outlook.com include:spf.messagelabs.com include:mktomail.com include:stspg-custo",
      "mer.com ip4:52.38.191.241 -all",
      "F5Bkf8aYNUTZwrEkaw2ss/rMNTWy9wTOKyKrIeQdD5YoMTFkYg9rjW275X1dSx5AWusuVqkf+caFIRtd63kGgw==",
      "hj-ownership=kbD4%B6@fEzJ",
      "amazonses:DUPTZ+5PC5cywK2wrfzQHVsalso6GCYZmw9b2wSAgMo=",
      "MS=ms92726142",
      "635557aa461593e8536643d878d7c78d698bcbb535e185853f5cfd526cafddfe"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com;fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=CA, stateOrProvinceName=Ontario, organizationName=Open Text Corporation, commonName=*.webroot.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA OV R36",
    "notBefore": "Sep 11 00:00:00 2025 GMT",
    "notAfter": "Oct 12 23:59:59 2026 GMT",
    "san": [
      "*.webroot.com",
      "webroot.com"
    ],
    "days_left": 15,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "45.60.151.109",
    "open": [
      21,
      25,
      53,
      110,
      143,
      993,
      995,
      1433,
      3306,
      3389,
      5900,
      6379,
      8000,
      8080,
      8443,
      8888,
      9090,
      9200
    ]
  },
  "https": {
    "status": 307,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Vercel"
  ],
  "cookies": [
    {
      "domain": ".webroot.com"
    },
    {
      "domain": ".webroot.com"
    },
    {
      "domain": ".webroot.com"
    },
    {
      "domain": ".webroot.com"
    },
    {
      "domain": ".webroot.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.webroot.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 308,
    "location": "https://webroot.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 307",
    "/redirect?next=https://evil-auditor.example/x -> 307",
    "/go?url=https://evil-auditor.example/x -> 307",
    "/url?url=https://evil-auditor.example/x -> 307"
  ],
  "paths": {
    "/robots.txt": 307,
    "/sitemap.xml": 307,
    "/.well-known/security.txt": 307,
    "/security.txt": 307,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 307,
    "/phpmyadmin/index.php": 307,
    "/server-status": 307,
    "/api/": 307
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=W342u9ABN8CsWzHJEUTnnprvsso64lGHcBzHIjXtP4A",
    "status-page-domain-verification=2tbgnrpnfp6b",
    "status-page-domain-verification=ry2yxtvp8dt4"
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
      "aia_ocsp": "http://ocsp.sectigo.com",
      "serial": 108557608789439541882417040425056681099,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.sectigo.com/SectigoPublicServerAuthenticationCAOVR36.crl"
      ],
      "subject_dn": "310b30090603550406130243413110300e060355040813074f6e746172696f311e301c060355040a13154f70656e205465787420436f72706f726174696f6e3116301406035504030c0d2a2e776562726f6f742e636f6d",
      "issuer_dn": "310b300906035504061302474231183016060355040a130f5365637469676f204c696d69746564313730350603550403132e5365637469676f205075626c6963205365727665722041757468656e7469636174696f6e204341204f5620523336",
      "not_before": "20250911000000",
      "not_after": "20261012235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/*?trpd=*",
      "/*?loc=*",
      "/*?WRSID=*",
      "/*?lang=*",
      "/au/en/cart",
      "/au/en/cart/",
      "/gb/en/cart",
      "/gb/en/cart/",
      "/gb/en/home/affiliates/",
      "/jp/ja/home/affiliates/",
      "/jp/ja/home/sem/",
      "/au/en/search",
      "/gb/en/search",
      "/hk/en/search",
      "/in/en/search"
    ]
  },
  "x12": {
    "status": 307
  },
  "x13": {
    "root_status": 307,
    "root_location": "https://www.webroot.com/",
    "http_status": 308,
    "p404_status": 307,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 307,
    "hsts": "max-age=63072000",
    "sitemap": {
      "urls": 192,
      "indexes": 0
    },
    "crl": {
      "url": "http://crl.sectigo.com/SectigoPublicServerAuthenticationCAOVR36.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 307
  },
  "x16": {
    "root_status": 307
  },
  "elapsed_s": 59.1,
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
