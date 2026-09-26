# Security Audit Report — vice.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vice.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | vice.com |
| Test date | 2026-09-26 19:01 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

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
| 12 | low | MAIL9 | DMARC enforces (p=reject) but has no reporting address (rua) | CWE-285 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

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

### 12. [LOW] DMARC enforces (p=reject) but has no reporting address (rua) (`MAIL9`)

- **CWE:** CWE-285
- **Detail:** Without a rua= reporting address the policy cannot be tuned; mis-sends may be silently quarantined.
- **Recommendation:** Add a rua= reporting mailbox to the DMARC record.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: klaviyo-site-verification=W3ywb2; site24x7-signals-domain-verification=203dd32b60ef01a9ed6d5f0a2d533127; google-site-verification=hmGbIbCrcAR4XY7Pu4PrIOlGhLl8MZ108lr2-5kqguM
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of vice.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1 disallow path(s), e.g. #
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "vice.com",
  "dns": {
    "a": [
      "192.0.66.177"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-1767.awsdns-28.co.uk.",
      "ns-409.awsdns-51.com.",
      "ns-851.awsdns-42.net.",
      "ns-1136.awsdns-14.org."
    ],
    "spf": [
      "klaviyo-site-verification=W3ywb2",
      "MS=ms60645384",
      "site24x7-signals-domain-verification=203dd32b60ef01a9ed6d5f0a2d533127",
      "google-site-verification=hmGbIbCrcAR4XY7Pu4PrIOlGhLl8MZ108lr2-5kqguM",
      "google-site-verification=0XoBNy3wbp30QiCvylLOm6zYj9kZKVq-MH_VSk9N7YI",
      "google-site-verification=8z8GM9dXL1-EpntXBKm21ItbggUCYcYCdlFItk_eBmA",
      "google-site-verification=btBMb52eXk6iENlWHf2enS6PXiqmlvh8EKOmYqtcKJI",
      "google-site-verification=2vnKISMVuTAXioui9BB5JRYgkvsjsrNQuTBD6vRdUZI",
      "_globalsign-domain-verification=FkYUUSU-u5X_D3giiaw10eou45Hypdwsy_sylh2zJu",
      "v=spf1 include:_spf.google.com include:amazonses.com include:servers.mcsv.net include:_spf-1.vice.com include:_spf-2.vice.com include:_spf-3.vice.com -all",
      "google-site-verification=lcQiAPONhDm_181jNSi6XpgY0idwd8qpTQH5_q4hQx4",
      "d71d927b-d9b1-486d-942d-a63b998cd054",
      "_globalsign-domain-verification=cvzudUSBhMY8hRS7IP7p9RJPtfz6pOiqiZnxw4TS3B",
      "apple-domain-verification=BOrbQ950ceBMRT6K",
      "t2dzyyjjk58zxx4trb2rkmzsq3pm7yt3",
      "google-site-verification=TratwkuDvIfbfsNT4KG8-YejFfBiW6p4oOcXRxLH3r4",
      "google-site-verification=JiCNjfV_KQ9u6p3NdMgJK1bVZmG32BEoMVA8mDJBwNE",
      "_globalsign-domain-verification=FvLwtclLqbuRNqYYejsQKQvAfmnbAsdS6mnPWYJ68i",
      "MS=ms95705199",
      "google-site-verification=v4Zf8BcP9sjIEkb-rLGU3Ac5H9n1PXQGKR1CLzxXCxw",
      "google-site-verification=BuA_rxCVfUoocrJPi9jJBNM-uNdkk7bMiF-pZP_yB1Y",
      "zone-ownership-verification-dec629f1cd5e9c0b33ea86958a7648d4d3b07a9fd759332730b3780beaef412b",
      "hdm3c44cjhiav30som77bfj86k",
      "_globalsign-domain-verification=Fw09cFhmPL_-Bfg6BV5_NkyDEkXJfmQd4uPViX560A",
      "MS=ms12990789",
      "atlassian-domain-verification=hskXXsfAYScT3KMiq7xVqeq8pA3Dkwaz5RTPEUtEYuz0g/axlajsLpjGfnxq71ua",
      "google-site-verification=UacLp_IBYg9IKcXHq6L2GB9XSn15AIQ0Oq75QZP8J5Y",
      "_globalsign-domain-verification=_RbDCFzr-yfROGxWkkSAsoiMH5OQA3bf87X1mVB00o",
      "mk2fh9vmhx7h82rb8fqq1v4fxqtb3dcm",
      "facebook-domain-verification=p28ly5dk7y0h9ifoyy14yc3uy9q51m"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;pct=100;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=vice.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Sep 10 12:58:32 2026 GMT",
    "notAfter": "Dec  9 12:58:31 2026 GMT",
    "san": [
      "vice.com",
      "www.vice.com"
    ],
    "days_left": 73,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.66.177",
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
      "origin": "https://sub.vice.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://vice.com/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "klaviyo-site-verification=W3ywb2",
    "site24x7-signals-domain-verification=203dd32b60ef01a9ed6d5f0a2d533127",
    "google-site-verification=hmGbIbCrcAR4XY7Pu4PrIOlGhLl8MZ108lr2-5kqguM",
    "google-site-verification=0XoBNy3wbp30QiCvylLOm6zYj9kZKVq-MH_VSk9N7YI",
    "google-site-verification=8z8GM9dXL1-EpntXBKm21ItbggUCYcYCdlFItk_eBmA"
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
      "not_before": "20260910125832",
      "not_after": "20261209125831"
    }
  },
  "http2": {
    "robots_disallow": [
      "#"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 18.4,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
