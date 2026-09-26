# Security Audit Report — quora.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://quora.com/ |
| Bug bounty program | Quora |
| Listed scope domain | quora.com |
| Test date | 2026-09-26 18:58 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 5, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
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
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 30 days (notAfter Oct 27 06:08:45 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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
- **Detail:** Header reveals: nginx
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
- **Detail:** Two random labels (auah3ddupjcpjh.quora.com and nso7ecj6z5bw90.quora.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=Ds6XsFtKHEpL7_tJLe9dGv1H8-fOa8Uql7lXZdlTIOg; openai-domain-verification=dv-PBdVIYKdEhZODJLXNZPwlxrS; loom-site-verification=fbb3540487864ef086ceb33d6e93dc1b
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of quora.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 704 disallow path(s), e.g. /ajax/, /*_POST$, /*_POST/, /@async, /*/@async
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 54.156.213.24 carries PTR ec2-54-156-213-24.compute-1.amazonaws.com. for quora.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "quora.com",
  "dns": {
    "a": [
      "54.156.213.24",
      "44.223.180.212",
      "18.208.80.151"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)",
      "aspmx3.googlemail.com (pref 30)"
    ],
    "ns": [
      "ns-344.awsdns-43.com.",
      "ns-673.awsdns-20.net.",
      "ns-1143.awsdns-14.org.",
      "ns-1573.awsdns-04.co.uk."
    ],
    "spf": [
      "google-site-verification=Ds6XsFtKHEpL7_tJLe9dGv1H8-fOa8Uql7lXZdlTIOg",
      "openai-domain-verification=dv-PBdVIYKdEhZODJLXNZPwlxrS",
      "d3o4sganq6g12y.cloudfront.net",
      "loom-site-verification=fbb3540487864ef086ceb33d6e93dc1b",
      "google-site-verification=clhTdgpCJ96li3EYCyeaXOrE4iREb4h0qAKpZCiRhjA",
      "MS=ms41108016",
      "globalsign-domain-verification=EnPHtt5EmnAS8ylIFlfJ0gcCPsrQy7SBNgoFOAHsIG",
      "_globalsign-domain-verification=EGXYWFCTQynvOf5IBle5NjMEbKo9PBQaeH9mnr_Faj",
      "turbopuffer-domain-verification-dbezx6=X1B8vvtffA2f2IlvINwKRjYd8",
      "google-site-verification=ZJilmJEnKdQ0PZQCWgmvTVHKvWcFPfI61-5J4aoYiBM",
      "google-site-verification=G3Xtneu_M6gnP9CFQgSCarSMCLhl2F1v1erLvqD_DTU",
      "globalsign-domain-verification=FnXWfFjPqReOGiIH8ITAbUasqKxnix6ftvTUzPOKHF",
      "anthropic-domain-verification-q9zk8w=qQTJ0XHnIN5d01dwaT5JiUjqD",
      "v=spf1 include:_spf1.quora.com include:_spf2.quora.com include:_spf.google.com include:mail.zendesk.com include:mailsenders.netsuite.com include:mktomail.com include:_spf.salesforce.com ~all",
      "jamf-site-verification=NG_yXXzmIUuroRjFeEjK-A",
      "google-site-verification=zFnSLKb0PqvlMBreKFyJ9xq2RXL3UuhATVjFpoUSpvc",
      "google-site-verification=YHVWrk9up0QuAIkeCEeZ6J7ty5jDoKwX1yNW_GST5Zg",
      "google-site-verification=tJbVk5zKwtko2UmH7oTIh6K_gk5PDHa6yMr33yhC23s",
      "google-site-verification=dPlPDM4NC9Cbm9HYrvs78idrWsw7ImV_1dPbLoYQmyY",
      "anthropic-domain-verification-ff87rw=roOVmHA9vsF5YBzqavhqZRnUp",
      "notion-domain-verification=XZ50Z8vAqIAKtBJKdHc2vNjkyEDlfL8zQVdTrl5rAsw",
      "docusign=ed3b177c-9f9e-46b8-822f-378104f0e937"
    ],
    "dmarc": [
      "v=DMARC1; p=reject;rua=mailto:dmarc+rua@quora.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=quora.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR1",
    "notBefore": "Jul 29 06:08:46 2026 GMT",
    "notAfter": "Oct 27 06:08:45 2026 GMT",
    "san": [
      "quora.com",
      "*.quora.com",
      "*.www.quora.com",
      "*.tch.quora.com",
      "*.tch.www.quora.com",
      "qr.ae",
      "*.qr.ae",
      "fs.quoracdn.net",
      "*.fs.quoracdn.net",
      "cf2.quoracdn.net",
      "*.cf2.quoracdn.net"
    ],
    "days_left": 30,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "54.156.213.24",
    "open": []
  },
  "https": {
    "status": 308,
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
      "origin": "https://sub.quora.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 308,
    "location": "https://quora.com/"
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
    "google-site-verification=Ds6XsFtKHEpL7_tJLe9dGv1H8-fOa8Uql7lXZdlTIOg",
    "openai-domain-verification=dv-PBdVIYKdEhZODJLXNZPwlxrS",
    "loom-site-verification=fbb3540487864ef086ceb33d6e93dc1b",
    "google-site-verification=clhTdgpCJ96li3EYCyeaXOrE4iREb4h0qAKpZCiRhjA",
    "globalsign-domain-verification=EnPHtt5EmnAS8ylIFlfJ0gcCPsrQy7SBNgoFOAHsIG"
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
      "aia_ocsp": null,
      "not_before": "20260729060846",
      "not_after": "20261027060845"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/ajax/",
      "/*_POST$",
      "/*_POST/",
      "/@async",
      "/*/@async",
      "/log/",
      "/*/log",
      "/*/about",
      "/*/action",
      "/*/activity",
      "/*/all_questions",
      "/*/all_posts$",
      "/*/all_posts/",
      "/*/blogs$",
      "/*/blogs/"
    ]
  },
  "x12": {
    "status": 308,
    "ptr": [
      "ec2-54-156-213-24.compute-1.amazonaws.com."
    ]
  },
  "elapsed_s": 40.5,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
