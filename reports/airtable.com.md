# Security Audit Report — airtable.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://airtable.com/ |
| Bug bounty program | Airtable |
| Listed scope domain | airtable.com |
| Test date | 2026-09-25 08:23 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 7 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |

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

## Evidence (raw response observations)

```json
{
  "domain": "airtable.com",
  "dns": {
    "a": [
      "3.169.55.99",
      "3.169.55.6",
      "3.169.55.126",
      "3.169.55.74"
    ],
    "aaaa": [
      "2600:9000:2834:2a00:0:fde1:c980:93a1",
      "2600:9000:2834:e000:0:fde1:c980:93a1",
      "2600:9000:2834:da00:0:fde1:c980:93a1",
      "2600:9000:2834:e200:0:fde1:c980:93a1",
      "2600:9000:2834:f800:0:fde1:c980:93a1",
      "2600:9000:2834:6000:0:fde1:c980:93a1",
      "2600:9000:2834:6e00:0:fde1:c980:93a1",
      "2600:9000:2834:7000:0:fde1:c980:93a1"
    ],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-1899.awsdns-45.co.uk.",
      "ns-1069.awsdns-05.org.",
      "ns-447.awsdns-55.com.",
      "ns-685.awsdns-21.net."
    ],
    "spf": [
      "beam-verification=Z9ucVlrllzaQ5SpJiJltJUsYSnHkBBIBjKadv4gsv5gddutH",
      "TAILSCALE-LCbD2Tan8BItnHOB3y0p",
      "cloudflare_dashboard_sso=c69d6361128a7dad5039e5b76e9b2cde",
      "apple-domain-verification=p7c2orfu38a1od5v",
      "box-domain-verification=7b0f06dc1db321da4355e0a57264582ef993ea8d5ec6a6a535c0da1fbb3716c4",
      "google-site-verification=euX05KyKBY2XRY3sMd51MBgkLgWSDt-D6HxEPbJZE4E",
      "stripe-verification=528727982b9408fcfaf4799d022aed98e6fe59f7bd19fb80c19eddf770808454",
      "cursor-domain-verification-7etnx9=AnyVPVFCmQJv6S6Hy1hH9cMUx",
      "google-site-verification=jCY0WH76zs_XUIsPN-CpVMrGxoER14S-qmba5HB-NOw",
      "ibmid=0555764c-fa27-4142-a90e-2ceb610f84ff",
      "onetrust-domain-verification=08cafae7e510435994fd87812abaa805",
      "postman-domain-verification=403414135fdd4de22ea8e6924a70b46d821cf0de2e9555c4b96e41c60231c9d84c37489d47b347411f991b446b0a7e0050b0bbff390999842ce3cc8c11cf8a93",
      "google-site-verification=AqsnhsVuEKjGgLyc8RXu6W3IPYDj-805B5Ofrt4ubp8",
      "google-site-verification=O-kfeG0vtUgAjQYn-gDpWkYWb_Kl8f3z9OjKswYlDug",
      "google-site-verification=yvhp-gxMyp-JZnuAm8Jx_EEoEjdik7VFz-wCpC4fklQ",
      "MS=ms57543645",
      "pylon-domain-verification-rhyhge=10SPcgfAp1cUzFOD1rW7HK9o6",
      "google-site-verification=7OYI2dFV51swegn-yfn7A9M6JKMyCLwnwVcoHriMkgw",
      "v=spf1 ip4:159.135.229.248 ip4:159.135.231.62 ip4:69.72.44.244 include:_spf.mailgun.org include:_spf.google.com include:_spf.salesforce.com mx ~all",
      "drift-domain-verification=25a66e35596d2f8afdc380e147dc2c84a92afd4020ca912c4eece0fe0ba31b07",
      "google-site-verification=DXt7gC5fDi-TwbqBj4qhJ0xZolvejBEbmsnmAWmid90",
      "openai-domain-verification=dv-cLdaKW0SF1WwsRiJz5GPTU3z",
      "zapier-domain-verification-challenge=8ee12b84-1c1e-467a-bbbf-a8f5f30f442e",
      "atlassian-domain-verification=SEoCkU1vByxZ6STi0tknyHIzfSDxB1F6wGGf/phI3fHsyIuu4doRXS/fXd0oadkC",
      "mgverify=c76c0b58ab94a58ab6470a3648cd01d386e0eded8faff1fe936c0f51605886c6",
      "docusign=48aed6b7-99ce-449e-b576-0e32ac39a3ca",
      "v=MCPv1; k=ed25519; p=G1cCoFkb5x1fTZwAJLb42JSNQB/sT9Cyx+colhPq7YI=",
      "docker-verification=d352c009-156f-4f43-a6c9-19c62d5f7f39",
      "sprout-social-092bd800-f204-4740-bf84-ae806843855d",
      "facebook-domain-verification=gfg0qo2au8cywd132m0itehi8rqhfq",
      "mgverify=4e7a1ef686139875f21ee18e629284f4b32b4bef29516a48d42806937db7489f",
      "jamf-site-verification=rHp6jc3H-3QFQbAJCz28xA",
      "google-site-verification=dKKmkVVrUbTHz22G3Mouc0xGoi_asVZMFspACVKmJoM"
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
    "days_left": 123,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.55.99",
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
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 96.4,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
