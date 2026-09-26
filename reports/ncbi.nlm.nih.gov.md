# Security Audit Report — ncbi.nlm.nih.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ncbi.nlm.nih.gov/ |
| Bug bounty program | U.S. Dept of Health & Human Services (HHS) |
| Listed scope domain | ncbi.nlm.nih.gov |
| Test date | 2026-09-26 22:11 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 2, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 18 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: clear
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Apache
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 10. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=r_gJSAUUa9jLHjrDalVHx6YDW-U-bIXvV5RAq4l1BEI; google-site-verification=nMmA8DdB_FATP9hChkks7To1ndl-jGwVn624WV03SJg
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.godaddy.com/ -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but ncbi.nlm.nih.gov is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 335 disallow path(s), e.g. /cgi-bin, /entrez, /stat, /COG, /Entrez
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 34.107.134.59 carries PTR 59.134.107.34.bc.googleusercontent.com. for ncbi.nlm.nih.gov.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xked1usjj5h0gd.html -> 404; error page/headers match: Apache.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 18. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The ncbi.nlm.nih.gov certificate lists an AIA OCSP responder (http://ocsp.godaddy.com/) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

## Evidence (raw response observations)

```json
{
  "domain": "ncbi.nlm.nih.gov",
  "dns": {
    "a": [
      "34.107.134.59"
    ],
    "aaaa": [
      "2600:1901:0:c831::"
    ],
    "cname": null,
    "mx": [
      "nihcesxway4.hub.nih.gov (pref 10)",
      "nihcesxway2.hub.nih.gov (pref 10)",
      "nihcesxway5.hub.nih.gov (pref 10)",
      "nihcesxway3.hub.nih.gov (pref 10)",
      "nihcesxway.hub.nih.gov (pref 10)"
    ],
    "ns": [
      "dns1-ncbi.ncbi.nlm.nih.gov.",
      "ns2.nih.gov.",
      "ns3.nih.gov.",
      "dns2-ncbi.ncbi.nlm.nih.gov.",
      "lhcns2.nlm.nih.gov.",
      "ns.nih.gov.",
      "lhcns1.nlm.nih.gov."
    ],
    "caa": [
      "0 issue \"letsencrypt.org\"",
      "0 issuewild \"letsencrypt.org\"",
      "0 issue \"godaddy.com\"",
      "0 issuewild \"godaddy.com\""
    ],
    "spf": [
      "64ae187888c443b49126410c89e19f91",
      "6ochlmevf91qg4f4aq6bo33ofk",
      "+UYkiJ9LhpTEGd+XduX0MaAclYq9qoJF4Ls5FJaAwl6LRx4aozocl8ZRea9MKMRaquSBJaZC52liuRb0rkxAMA==",
      "21mn4fyhz69y985h80bcyrf4vjqjl0ln",
      "google-site-verification=r_gJSAUUa9jLHjrDalVHx6YDW-U-bIXvV5RAq4l1BEI",
      "v=spf1 ip4:130.14.26.0/25 ip4:165.112.9.132 ip4:130.14.19.0/24 ip4:130.14.28.0/24 ip4:10.65.8.60 ip4:130.14.22.0/24 ip4:128.231.90.64/26 ip4:165.112.13.0/26 ip6:2607:f220:0404:8104::0/64 ip6:2607:f220:402:1a01::0/64 ",
      "ip4:63.150.153.0/28 ip4:63.236.109.192/28 ip4:63.236.97.64/27 ip4:66.77.66.64/26 ip4:63.236.105.192/28 ip4:63.236.106.128/27 ip4:68.177.111.128/26 ip4:156.40.79.128/25 ip4:165.112.194.0/25 ",
      "ip6:2607:f220:041e:4260::41/64 ip6:2607:f220:041e:4260::42/64 ip6:2607:f220:041e:4260::15/64 ip6:2607:f220:041e:4260::16/64 ip6:2607:f220:41f:4260::132/64 include:nih.gov -all",
      "5ongv773afed7ghag3eubs9v6c",
      "google-site-verification=nMmA8DdB_FATP9hChkks7To1ndl-jGwVn624WV03SJg"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:8idhoybh@ag.us.dmarcian.com,mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:8idhoybh@fr.us.dmarcian.com; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.ncbi.nlm.nih.gov",
    "issuer": "countryName=US, organizationName=GoDaddy.com, commonName=GoDaddy TLS Intermediate CA DV - R1v1",
    "notBefore": "Aug 28 16:31:19 2026 GMT",
    "notAfter": "Mar 14 16:31:19 2027 GMT",
    "san": [
      "*.ncbi.nlm.nih.gov",
      "ncbi.nlm.nih.gov"
    ],
    "days_left": 168,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.107.134.59",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "National Center for Biotechnology Information"
  },
  "mixed_content": [],
  "tech": [
    "Server: Apache"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.ncbi.nlm.nih.gov",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ncbi.nlm.nih.gov:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=r_gJSAUUa9jLHjrDalVHx6YDW-U-bIXvV5RAq4l1BEI",
    "google-site-verification=nMmA8DdB_FATP9hChkks7To1ndl-jGwVn624WV03SJg"
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
      "aia_ocsp": "http://ocsp.godaddy.com/",
      "not_before": "20260828163119",
      "not_after": "20270314163119"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/cgi-bin",
      "/entrez",
      "/stat",
      "/COG",
      "/Entrez",
      "/mailman",
      "/myncbi",
      "/sutils",
      "/Taxonomy/Selector",
      "/Taxonomy/CommonTree",
      "/entrez/sutils",
      "/mapview",
      "/blast/BlastAlign.cgi",
      "/blast/bl2seq/wblast2.cgi",
      "/portal"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "59.134.107.34.bc.googleusercontent.com."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 36.0,
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
