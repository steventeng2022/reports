# Security Audit Report — pinterest.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pinterest.com/ |
| Bug bounty program | Pinterest |
| Listed scope domain | pinterest.com |
| Test date | 2026-09-26 18:57 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 4, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

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
- **Detail:** Apex TXT records with verification/token content: postman-domain-verification=142fa709f30458c470545ae61a557bdc54690989c11d4bc4c1fa; paloaltonetworks-site-verification=87ccfc26e7b2486ad8e407c6ed99e788937e68856e309; twilio-domain-verification=b2a4a22e61255ba1b4a7ca8dd87f861e
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of pinterest.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 653 disallow path(s), e.g. /*/*/*/_tools/*, /*/*/*/more_ideas/, /*/*/_tools/*, /*/*/activity/*, /*/*/group/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "pinterest.com",
  "dns": {
    "a": [
      "151.101.192.84",
      "151.101.128.84",
      "151.101.0.84",
      "151.101.64.84"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt3.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns5.pinterest.com.",
      "ns9.pinterest.com.",
      "ns6.pinterest.com.",
      "ns10.pinterest.com."
    ],
    "spf": [
      "ZOOM_verify_noGVfZnQStK_Xkext4FibQ",
      "MS=ms18016700",
      "postman-domain-verification=142fa709f30458c470545ae61a557bdc54690989c11d4bc4c1fa0024f2633301472dede2e6f991eb8f711acc29e99803b459917344d52b9bd0c96cdd4e9b9609",
      "TAILSCALE-p6rAjPzJIKMJiQCiFQ1p",
      "paloaltonetworks-site-verification=87ccfc26e7b2486ad8e407c6ed99e788937e68856e3091665b3a942fb44f7646",
      "twilio-domain-verification=b2a4a22e61255ba1b4a7ca8dd87f861e",
      "c5ce3936-9dec-4ee6-b044-55cb8ea62f04",
      "freepik-domain-verification=c716162ae55dce0d8daa58814f14aa8f",
      "docker-verification=b02df65b-3c5d-4537-b019-4537f40d5d6e",
      "loom-site-verification=5a36a427d0674ac5b53de45d12741f68",
      "00D1N000000GSLM=1TBPW00000002WT",
      "1password-site-verification=WCNWOT5Q6BDF3JCLBGSCDZO4AE",
      "apple-domain-verification=fR4SkeFsfvTQqwcL",
      "miro-verification=8739d427e9a419960e9fbb1f86941c3b74e47415",
      "liveramp-site-verification=vkCU0rzeleXDe3XcsQSxGrcPwe9HTOJ1Iz9ZXKTXAJg",
      "00DOt00000pkQbd=1TBOt0000000PmP",
      "canva-site-verification=a6iVl7OoKkmq61eoJl2EXQ",
      "google-site-verification=417aaeLwriDzNgFX-W8AC4BfpRxlO_h-XDkUL0vFflM",
      "v=spf1 redirect=_spf.pinterest.com",
      "tiktok-developers-site-verification=b3h14NLD33KKuBsuEh2JssxoMIzGTYbw",
      "sprout-social-668b8426-fc96-4bdb-b970-5e3ee11884c9",
      "gamma-domain-verification-x88yj9=4PkqRMwC3FhyTAYr0aoXhOCTH",
      "google-site-verification=ROV7s4DFtQ5T6mqp_PnThPrA3J8cLSSfIvmDJCcM-Rk",
      "cursor-domain-verification-vyc8km=a5aBskJG8rDWOTCVrmI6gBHfb",
      "openai-domain-verification=dv-FvRuqwrE1vLdGpJp5PlbPvQr",
      "CKO=cli_2yspwwmpzjpezmdjr5ivf4kbcu",
      "loom-verification=9088334975",
      "00DOt000015E6TZ=1TBOt0000000bfV",
      "browserstack-domain-verification=b57d2484-2df5-41d4-9b7e-5e8fed11b781",
      "happeo-site-verification=38d7bd5177a34890878877d099afe22f",
      "google-site-verification=NL3G6_2q9FrmNnriQD18LIAVfmthnoRMIatQzD_MhTI",
      "yandex-verification: 9448cd71fe506a76",
      "facebook-domain-verification=2pkj9rox53bgoy96jten5vrid77mv7",
      "applause-verification:2d72e729-a6d6-47c8-82f9-8adc27830272",
      "mgverify=a37224d064fb37fa047c67fecac02932e7cdc68e4a12addcb9762e52efa7c1f1",
      "docusign=181669b6-686c-408b-ac15-076711ffc372",
      "atlassian-domain-verification=VvwbKGkKpnJiNIesXRcvnY12kzfIjT/wvmUb20l7mKjTN9IseYMUKstqdhwnSe59",
      "work-accounts-domain-verification=xWymOmluA0vPNLJQaf4StWL68TsfRh",
      "CKO=cli_cyft6no6jdbuzmltnrp3egprzy",
      "anthropic-domain-verification-c1b7dr=bBfPNbyIXzGWEhqJ24pOJ6W0u",
      "arkose-domain-verify=2cnrb3du4uwyva8jqv9kun47z36982e6",
      "dcao2catgy34x.cloudfront.net",
      "docusign=7247a7f7-68c2-4f62-bb95-06c52d85d646"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; pct=100; rua=mailto:o4khm-8732@rua.dmarc.emailanalyst.com; ruf=mailto:o4khm-8732@ruf.dmarc.emailanalyst.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Francisco, organizationName=Pinterest, Inc., commonName=*.pinterest.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Aug 13 00:00:00 2026 GMT",
    "notAfter": "Feb 26 23:59:59 2027 GMT",
    "san": [
      "*.pinterest.com",
      "*.pinimg.com",
      "*.pinterest.info",
      "*.pinterest.engineering",
      "*.pinterestmail.com",
      "*.pinterest.at",
      "*.pinterest.ch",
      "*.pinterest.de",
      "*.pinterest.dk",
      "*.pinterest.ie",
      "*.pinterest.jp",
      "*.pinterest.kr",
      "*.pinterest.mx",
      "*.pinterest.pt",
      "*.pinterest.se",
      "*.pinterest.co.at",
      "*.pinterest.co.kr",
      "*.pinterest.co.uk",
      "*.pinterest.com.mx",
      "pin.it",
      "pinterest.com",
      "pinimg.com",
      "pinterest.info",
      "pinterest.engineering",
      "pinterestmail.com",
      "pinterest.at",
      "pinterest.ch",
      "pinterest.de",
      "pinterest.dk",
      "pinterest.ie",
      "pinterest.jp",
      "pinterest.kr",
      "pinterest.mx",
      "pinterest.pt",
      "pinterest.se",
      "pinterest.co.at",
      "pinterest.co.kr",
      "pinterest.co.uk",
      "pinterest.com.mx",
      "*.pinterest.ca",
      "*.pinterest.fr",
      "pinterest.ca",
      "pinterest.fr",
      "pinterest.com.au",
      "*.pinterest.com.au",
      "pinterest.nz",
      "*.pinterest.nz",
      "pinterest.es",
      "*.pinterest.es",
      "pinterest.cl",
      "*.pinterest.cl",
      "pinterest.ph",
      "*.pinterest.ph",
      "pinterest.in",
      "*.pinterest.in",
      "pinterest.co.in",
      "*.pinterest.co.in",
      "pinterest.be",
      "*.pinterest.be",
      "pinterest.pe",
      "*.pinterest.pe",
      "pinterest.co",
      "*.pinterest.co",
      "pinterest.com.py",
      "*.pinterest.com.py",
      "pinterest.com.bo",
      "*.pinterest.com.bo",
      "pinterest.com.ec",
      "*.pinterest.com.ec",
      "pinterest.ec",
      "*.pinterest.ec",
      "pinterest.hu",
      "*.pinterest.hu",
      "pinterest.com.vn",
      "*.pinterest.com.vn",
      "pinterest.it",
      "*.pinterest.it",
      "pinterest.com.pe",
      "*.pinterest.com.pe",
      "pinterest.com.uy",
      "*.pinterest.com.uy",
      "pinterest.co.nz",
      "*.pinterest.co.nz",
      "pinterest.uk",
      "*.pinterest.uk",
      "pinterest.vn",
      "*.pinterest.vn",
      "pinterest.id",
      "*.pinterest.id",
      "pinterest.th",
      "*.pinterest.th",
      "pinterest.tw",
      "*.pinterest.tw",
      "pinterest.nl",
      "*.pinterest.nl",
      "*.testing.pinterest.com"
    ],
    "days_left": 153,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.192.84",
    "open": []
  },
  "https": {
    "status": 308,
    "content_type": "",
    "title": ""
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
      "origin": "https://sub.pinterest.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 308,
    "location": "https://pinterest.com/"
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
  "apex_txt": [
    "postman-domain-verification=142fa709f30458c470545ae61a557bdc54690989c11d4bc4c1fa",
    "paloaltonetworks-site-verification=87ccfc26e7b2486ad8e407c6ed99e788937e68856e309",
    "twilio-domain-verification=b2a4a22e61255ba1b4a7ca8dd87f861e",
    "freepik-domain-verification=c716162ae55dce0d8daa58814f14aa8f",
    "docker-verification=b02df65b-3c5d-4537-b019-4537f40d5d6e"
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
      "not_before": "20260813000000",
      "not_after": "20270226235959"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/*/*/*/_tools/*",
      "/*/*/*/more_ideas/",
      "/*/*/_tools/*",
      "/*/*/activity/*",
      "/*/*/group/",
      "/*/*/invite/",
      "/*/*/more_ideas/*",
      "/*/?*amp_client_id*",
      "/*/?z=1",
      "/*/__wishlist__/*",
      "/*/_activities/*",
      "/*/_activity/*",
      "/*/_community/*",
      "/*/_created/*",
      "/*/_followers/*"
    ]
  },
  "x12": {
    "status": 308
  },
  "elapsed_s": 13.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
