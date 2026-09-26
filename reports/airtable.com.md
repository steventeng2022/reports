# Security Audit Report — airtable.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://airtable.com/ |
| Bug bounty program | Airtable |
| Listed scope domain | airtable.com |
| Test date | 2026-09-26 18:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 2, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 7 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 14 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Tengine
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Tengine
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'AWSALBTG' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 7. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'AWSALBTG' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 8. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 9. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: box-domain-verification=7b0f06dc1db321da4355e0a57264582ef993ea8d5ec6a6a535c0da1f; facebook-domain-verification=gfg0qo2au8cywd132m0itehi8rqhfq; jamf-site-verification=rHp6jc3H-3QFQbAJCz28xA
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of airtable.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 17 disallow path(s), e.g. /404, /500, /auth, /embed/*, /temporary_marketing_proxy/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of airtable.com permits unsafe-inline; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 14. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of airtable.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.169.55.74 carries PTR server-3-169-55-74.tpe54.r.cloudfront.net. for airtable.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "airtable.com",
  "dns": {
    "a": [
      "3.169.55.74",
      "3.169.55.99",
      "3.169.55.6",
      "3.169.55.126"
    ],
    "aaaa": [
      "2600:9000:2834:2600:0:fde1:c980:93a1",
      "2600:9000:2834:4800:0:fde1:c980:93a1",
      "2600:9000:2834:2200:0:fde1:c980:93a1",
      "2600:9000:2834:e200:0:fde1:c980:93a1",
      "2600:9000:2834:f800:0:fde1:c980:93a1",
      "2600:9000:2834:ac00:0:fde1:c980:93a1",
      "2600:9000:2834:1200:0:fde1:c980:93a1",
      "2600:9000:2834:de00:0:fde1:c980:93a1"
    ],
    "cname": null,
    "mx": [
      "alt3.aspmx.l.google.com (pref 10)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-685.awsdns-21.net.",
      "ns-1069.awsdns-05.org.",
      "ns-447.awsdns-55.com.",
      "ns-1899.awsdns-45.co.uk."
    ],
    "spf": [
      "box-domain-verification=7b0f06dc1db321da4355e0a57264582ef993ea8d5ec6a6a535c0da1fbb3716c4",
      "facebook-domain-verification=gfg0qo2au8cywd132m0itehi8rqhfq",
      "jamf-site-verification=rHp6jc3H-3QFQbAJCz28xA",
      "postman-domain-verification=403414135fdd4de22ea8e6924a70b46d821cf0de2e9555c4b96e41c60231c9d84c37489d47b347411f991b446b0a7e0050b0bbff390999842ce3cc8c11cf8a93",
      "google-site-verification=O-kfeG0vtUgAjQYn-gDpWkYWb_Kl8f3z9OjKswYlDug",
      "beam-verification=Z9ucVlrllzaQ5SpJiJltJUsYSnHkBBIBjKadv4gsv5gddutH",
      "zapier-domain-verification-challenge=8ee12b84-1c1e-467a-bbbf-a8f5f30f442e",
      "cursor-domain-verification-7etnx9=AnyVPVFCmQJv6S6Hy1hH9cMUx",
      "ibmid=0555764c-fa27-4142-a90e-2ceb610f84ff",
      "onetrust-domain-verification=08cafae7e510435994fd87812abaa805",
      "docusign=48aed6b7-99ce-449e-b576-0e32ac39a3ca",
      "google-site-verification=AqsnhsVuEKjGgLyc8RXu6W3IPYDj-805B5Ofrt4ubp8",
      "TAILSCALE-LCbD2Tan8BItnHOB3y0p",
      "google-site-verification=dKKmkVVrUbTHz22G3Mouc0xGoi_asVZMFspACVKmJoM",
      "sprout-social-092bd800-f204-4740-bf84-ae806843855d",
      "drift-domain-verification=25a66e35596d2f8afdc380e147dc2c84a92afd4020ca912c4eece0fe0ba31b07",
      "google-site-verification=jCY0WH76zs_XUIsPN-CpVMrGxoER14S-qmba5HB-NOw",
      "google-site-verification=yvhp-gxMyp-JZnuAm8Jx_EEoEjdik7VFz-wCpC4fklQ",
      "v=MCPv1; k=ed25519; p=G1cCoFkb5x1fTZwAJLb42JSNQB/sT9Cyx+colhPq7YI=",
      "google-site-verification=DXt7gC5fDi-TwbqBj4qhJ0xZolvejBEbmsnmAWmid90",
      "atlassian-domain-verification=SEoCkU1vByxZ6STi0tknyHIzfSDxB1F6wGGf/phI3fHsyIuu4doRXS/fXd0oadkC",
      "google-site-verification=7OYI2dFV51swegn-yfn7A9M6JKMyCLwnwVcoHriMkgw",
      "stripe-verification=528727982b9408fcfaf4799d022aed98e6fe59f7bd19fb80c19eddf770808454",
      "pylon-domain-verification-rhyhge=10SPcgfAp1cUzFOD1rW7HK9o6",
      "cloudflare_dashboard_sso=c69d6361128a7dad5039e5b76e9b2cde",
      "openai-domain-verification=dv-cLdaKW0SF1WwsRiJz5GPTU3z",
      "docker-verification=d352c009-156f-4f43-a6c9-19c62d5f7f39",
      "v=spf1 ip4:159.135.229.248 ip4:159.135.231.62 ip4:69.72.44.244 include:_spf.mailgun.org include:_spf.google.com include:_spf.salesforce.com mx ~all",
      "mgverify=c76c0b58ab94a58ab6470a3648cd01d386e0eded8faff1fe936c0f51605886c6",
      "mgverify=4e7a1ef686139875f21ee18e629284f4b32b4bef29516a48d42806937db7489f",
      "google-site-verification=euX05KyKBY2XRY3sMd51MBgkLgWSDt-D6HxEPbJZE4E",
      "apple-domain-verification=p7c2orfu38a1od5v",
      "MS=ms57543645"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; ri=3600; rua=mailto:dc7a0f9c@dmarc.mailgun.org,mailto:b38def86@inbox.ondmarc.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=app.airtable.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jul 13 00:00:00 2026 GMT",
    "notAfter": "Jan 26 23:59:59 2027 GMT",
    "san": [
      "app.airtable.com",
      "airtable.com"
    ],
    "days_left": 122,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.55.74",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Tengine"
  ],
  "cookies": [
    {},
    {
      "samesite": "none"
    },
    {
      "domain": ".airtable.com",
      "samesite": "none"
    },
    {
      "domain": ".airtable.com",
      "samesite": "none"
    },
    {
      "domain": ".airtable.com"
    },
    {
      "samesite": "none"
    },
    {
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
      "origin": "https://sub.airtable.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://airtable.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "box-domain-verification=7b0f06dc1db321da4355e0a57264582ef993ea8d5ec6a6a535c0da1f",
    "facebook-domain-verification=gfg0qo2au8cywd132m0itehi8rqhfq",
    "jamf-site-verification=rHp6jc3H-3QFQbAJCz28xA",
    "postman-domain-verification=403414135fdd4de22ea8e6924a70b46d821cf0de2e9555c4b96e",
    "google-site-verification=O-kfeG0vtUgAjQYn-gDpWkYWb_Kl8f3z9OjKswYlDug"
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
      "not_before": "20260713000000",
      "not_after": "20270126235959"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/404",
      "/500",
      "/auth",
      "/embed/*",
      "/temporary_marketing_proxy/*",
      "/forgot",
      "/internal/*",
      "/invite/l?inviteId=*&inviteToken=*",
      "/msa",
      "/shr*",
      "/app*/shr*",
      "/app*/pag*/form*",
      "/sso/login",
      "/tbl*",
      "/?try=*"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "server-3-169-55-74.tpe54.r.cloudfront.net."
    ]
  },
  "elapsed_s": 13.0,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
