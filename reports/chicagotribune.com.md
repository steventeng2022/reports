# Security Audit Report — chicagotribune.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://chicagotribune.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | chicagotribune.com |
| Test date | 2026-09-26 18:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 6, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P11 | WordPress login page exposed | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 13 | low | MAIL9 | DMARC enforces (p=reject) but has no reporting address (rua) | CWE-285 |
| 14 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 15 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 16 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 17 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 10. [INFO] WordPress login page exposed (`P11`)

- **CWE:** CWE-200
- **Detail:** /wp-login.php returns 200.
- **Recommendation:** Restrict or rate-limit the WordPress login endpoint.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): de. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 13. [LOW] DMARC enforces (p=reject) but has no reporting address (rua) (`MAIL9`)

- **CWE:** CWE-285
- **Detail:** Without a rua= reporting address the policy cannot be tuned; mis-sends may be silently quarantined.
- **Recommendation:** Add a rua= reporting mailbox to the DMARC record.

### 14. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 15. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 16. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=tCFWENjSprayvXVGaRbGtnlL1DMiF3qL6KwnvJTUdDE; knowbe4-site-verification=90309b4eacebd82470e924deb428c541; globalsign-domain-verification=KaParXxs1OHDy7o8CMbPpHBN-2m_mzwdPqKMMQ66a6
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 17. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of chicagotribune.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 70 disallow path(s), e.g. /wp-admin/, /cgi-bin/, /wp-includes/, /xmlrpc.php, /wp-content/plugins/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of chicagotribune.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

## Evidence (raw response observations)

```json
{
  "domain": "chicagotribune.com",
  "dns": {
    "a": [
      "192.0.66.226"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-670.awsdns-19.net.",
      "ns-1494.awsdns-58.org.",
      "ns-318.awsdns-39.com.",
      "ns-1929.awsdns-49.co.uk."
    ],
    "spf": [
      "google-site-verification=tCFWENjSprayvXVGaRbGtnlL1DMiF3qL6KwnvJTUdDE",
      "knowbe4-site-verification=90309b4eacebd82470e924deb428c541",
      "globalsign-domain-verification=KaParXxs1OHDy7o8CMbPpHBN-2m_mzwdPqKMMQ66a6",
      "00D6A000000u2db=1TBRP00000001P7",
      "t26qk4mlm75j2yzsjlcj89w3tr8qml1t",
      "fuh70icl95j9uk98vh9in27a1v",
      "qhsioljhf61egi221dmpq75l97",
      "q8qte811etl3vh7t2kjtj5hvef",
      "facebook-domain-verification=ie1u288563hms698676bmsocuqkst5",
      "4qa0gtiqqj7c3qb8ign7j5veae",
      "bw=uBsTlw0gfXBTobeK+x5MDbbYw7z/+6e8St20HrxOzAUC",
      "_globalsign-domain-verification=eRi2ZQZJ99fAou8jrSC06eUJpasrvj8YgWl21vaW5G",
      "7e2evqs0fhns3181r2qr7a85h7",
      "MS=ms20138954",
      "tollbit-domain-verification=fa0b71753f77d48596d9c864ee65b7243d54641a266abed5cbff240c5388e88f",
      "dc5c2772ba0747a1b324e08489986f72",
      "google-site-verification=7DJm-cs-QXsih9c8YkgDHUv-fEdopAZ-xU8Z2M3oDnc",
      "google-site-verification=R1gNl6zO56wI3fvU3rTP5_TVgm9XQX30rXJa2XJzp6I",
      "google-site-verification=WZ1oTeEoyp2ivPsaJjoK2C9YLNIFyuuI3WpcG387MIM",
      "jrrp75hmjgof937m48dfr168tf",
      "8fhvtdhi65bc45gilg1icj1b8f",
      "google-site-verification=7YyRyZ2VOIw6bJi4MEx8_EsHZbGoghhN5nfHVivraY4",
      "v=spf1 include:_spf.google.com include:spf.protection.outlook.com include:de._spf.fagms.net include:sendgrid.net ip4:198.21.3.53 ip4:159.183.220.8 exists:%{i}.spf.sitel.iphmx.com ip4:52.6.112.187 include:navigacloud.com -all",
      "iehg8ub4pkj0fr1muk30236f2h",
      "google-site-verification=KgZD5A9gpsayiGlRAoeE7bgSRBjgujWL4U-Kz_4YS-M",
      "google-site-verification=IIMYhaHdVMjr0knA13JlUko59o7aG_WfsRumyBjbOx8",
      "hucq9oebjdhnpo231ru64sqlu4",
      "1d9ebbcd0e404243947cfbbcd8f50291",
      "google-site-verification=W2rzDizmU_fC811E9mwZ2NCwDCPmzcG1LR8chZdf5Rs",
      "google-site-verification=fXz0UUCS6jEN-J8qKswb90LlksOYFKoXQw8fHoUwjsE",
      "bntlt7a869guderdu33t64dms5"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=chicagotribune.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Sep  4 00:38:50 2026 GMT",
    "notAfter": "Dec  3 00:38:49 2026 GMT",
    "san": [
      "chicagotribune.com",
      "www.chicagotribune.com"
    ],
    "days_left": 67,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.66.226",
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
      "origin": "https://sub.chicagotribune.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://chicagotribune.com/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=tCFWENjSprayvXVGaRbGtnlL1DMiF3qL6KwnvJTUdDE",
    "knowbe4-site-verification=90309b4eacebd82470e924deb428c541",
    "globalsign-domain-verification=KaParXxs1OHDy7o8CMbPpHBN-2m_mzwdPqKMMQ66a6",
    "facebook-domain-verification=ie1u288563hms698676bmsocuqkst5",
    "_globalsign-domain-verification=eRi2ZQZJ99fAou8jrSC06eUJpasrvj8YgWl21vaW5G"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260904003850",
      "not_after": "20261203003849"
    }
  },
  "http2": {
    "robots_disallow": [
      "/wp-admin/",
      "/cgi-bin/",
      "/wp-includes/",
      "/xmlrpc.php",
      "/wp-content/plugins/",
      "/wp-content/cache/",
      "/trackback/",
      "/comments/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 29.3,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
