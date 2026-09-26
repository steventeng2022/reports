# Security Audit Report — cloudflare.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cloudflare.com/ |
| Bug bounty program | Cloudflare |
| Listed scope domain | cloudflare.com |
| Test date | 2026-09-26 18:48 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 16 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 17 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.132.229:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.132.229:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=15780000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 12. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 15. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.cloudflare.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 16. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: canva-site-verification=oOyaVnHC-OiFoR1BPvetNA; liveramp-site-verification=EhH1MqgwbndTWl1AN64hOTKz7hc1s80yUpchLbgpfY0; apple-domain-verification=DNnWJoArJobFJKhJ
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 17. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of cloudflare.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "cloudflare.com",
  "dns": {
    "a": [
      "104.16.132.229",
      "104.16.133.229"
    ],
    "aaaa": [
      "2606:4700::6810:84e5",
      "2606:4700::6810:85e5"
    ],
    "cname": null,
    "mx": [
      "mxa-canary.global.inbound.cf-emailsecurity.net (pref 5)",
      "mxa.global.inbound.cf-emailsecurity.net (pref 10)",
      "mxb-canary.global.inbound.cf-emailsecurity.net (pref 5)",
      "mxb.global.inbound.cf-emailsecurity.net (pref 10)"
    ],
    "ns": [
      "ns6.cloudflare.com.",
      "ns3.cloudflare.com.",
      "ns5.cloudflare.com.",
      "ns4.cloudflare.com.",
      "ns7.cloudflare.com."
    ],
    "spf": [
      "MS=ms70274184",
      "canva-site-verification=oOyaVnHC-OiFoR1BPvetNA",
      "liveramp-site-verification=EhH1MqgwbndTWl1AN64hOTKz7hc1s80yUpchLbgpfY0",
      "apple-domain-verification=DNnWJoArJobFJKhJ",
      "facebook-domain-verification=h9mm6zopj6p2po54woa16m5bskm6oo",
      "DirectFedAuthUrl=https://cloudflare-security.cloudflareaccess.com/cdn-cgi/access/sso/saml/ebec933773c69c93420d13e6776adb8c4a190f6281f9d132bcebd7dcb0967bdd",
      "_wkjc0fot0d7qrvrdt78bxkj2e2o67d2",
      "_saml-domain-challenge.2dc00405-79cd-457b-b288-a119c6f0c7b7.71996d53-d178-4ba9-bef4-7f7e46edab74.cloudflare.com=1c8736fd-84b2-4197-985f-3fb2852f2457",
      "asv=894f6d1f9f83bcf44e4b1bc40bc1c4aa",
      "databank-domain-verification-hkehd2=fzgu4kmbZwMoW99zENgO4u8NL",
      "jamf-site-verification=c-eUvHBbhgFxMulFSY-QJQ",
      "stripe-verification=bf1a94e6b16ace2502a4a7fff574a25c8a45291054960c883c59be39d1788db9",
      "v=spf1 ip4:199.15.212.0/22 ip4:173.245.48.0/20 include:_spf.google.com include:spf1.mcsv.net include:spf.mandrillapp.com include:mail.zendesk.com include:stspg-customer.com include:_spf.salesforce.com -all",
      "creatopy-domain-verification=97d2ca50-9b6f-4a21-9bdb-fbb630e4cec7",
      "google-site-verification=ZdlQZLBBAPkxeFTCM1rpiB_ibtGff_JF5KllNKwDR9I",
      "_neqmkgaq1lq9it5s8qmetrhbnu121wb",
      "atlassian-domain-verification=WxxKyN9aLnjEsoOjUYI6T0bb5vcqmKzaIkC9Rx2QkNb751G3LL/cus8/ZDOgh8xB",
      "DirectFedAuthUrl=https://cloudflare-security.cloudflareaccess.com/cdn-cgi/access/sso/saml/dba6756ad312fc13c45f705cf7f5e87f4d658be016c41f950329aa4085b3abc1",
      "docker-verification=c578e21c-34fb-4474-9b90-d55ee4cba10c",
      "uber-domain-verification=58086039-150a-42a4-a4be-b4032921aa0f",
      "onetrust-domain-verification=bd5cd08a1e9644799fdb98ed7d60c9cb",
      "ZOOM_verify_7LFBvOO9SIigypFG2xRlMA",
      "drift-domain-verification=f037808a26ae8b25bc13b1f1f2b4c3e0f78c03e67f24cefdd4ec520efa8e719f",
      "miro-verification=bdd7dfa0a49adfb43ad6ddfaf797633246c07356",
      "logmein-verification-code=b3433c86-3823-4808-8a7e-58042469f654",
      "stripe-verification=5096d01ff2cf194285dd51cae18f24fa9c26dc928cebac3636d462b4c6925623",
      "cisco-ci-domain-verification=27e926884619804ef987ae4aa1c4168f6b152ada84f4c8bfc74eb2bd2912ad72",
      "status-page-domain-verification=r14frwljwbxs",
      "google-site-verification=C7thfNeXVahkVhniiqTI1iSVnElKR_kBBtnEHkeGDlo"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; adkim=r; aspf=r; pct=100; rua=mailto:a1c47f179bc04efd8ee4dcd4d85dfc65@dmarc-reports.cloudflare.net,mailto:rua@cloudflare.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=cloudflare.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep  5 22:29:39 2026 GMT",
    "notAfter": "Dec  4 23:29:33 2026 GMT",
    "san": [
      "cloudflare.com",
      "ns.cloudflare.com",
      "*.ns.cloudflare.com",
      "*.secondary.cloudflare.com",
      "secondary.cloudflare.com"
    ],
    "days_left": 69,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.16.132.229",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "cloudflare.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.cloudflare.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.cloudflare.com/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "canva-site-verification=oOyaVnHC-OiFoR1BPvetNA",
    "liveramp-site-verification=EhH1MqgwbndTWl1AN64hOTKz7hc1s80yUpchLbgpfY0",
    "apple-domain-verification=DNnWJoArJobFJKhJ",
    "facebook-domain-verification=h9mm6zopj6p2po54woa16m5bskm6oo",
    "databank-domain-verification-hkehd2=fzgu4kmbZwMoW99zENgO4u8NL"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260905222939",
      "not_after": "20261204232933"
    }
  },
  "http2": {
    "hsts_preloaded": true
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 4.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
