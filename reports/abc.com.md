# Security Audit Report — abc.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://abc.com/ |
| Bug bounty program | The Walt Disney Company |
| Listed scope domain | abc.com |
| Test date | 2026-09-25 08:09 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 3, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 11 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | CT1 | 43 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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

### 10. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'country' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 11. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'country' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [INFO] 43 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.abc.com, api.partners.abc.com, cdn.mktg.abc.com, cdn.video.abc.com, dev.cd.abc.com, dev.galaxy.abc.com, fcast.cdn.abc.com, fcast.qa.cdn.abc.com, help.abc.com, ll.media.abc.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "abc.com",
  "dns": {
    "a": [
      "3.169.121.28",
      "3.169.121.22",
      "3.169.121.54",
      "3.169.121.125"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "abc-com.mail.protection.outlook.com (pref 5)"
    ],
    "ns": [
      "ns-1869.awsdns-41.co.uk.",
      "ns-1368.awsdns-43.org.",
      "ns-318.awsdns-39.com.",
      "ns-736.awsdns-28.net."
    ],
    "spf": [
      "v=spf1 include:spf.disney.com -all",
      "nintex.5f22e1f0a5ad340038cdb208",
      "42357818",
      "intersight=e61370b3eacaf63c12b058d9c7b287aa1a9fdbc17d6958aaf1036e5c54f90502",
      "ECZjYXSxe4CRnyGjS8E1nRw2keq1hV77Z66acQb6JhwQk14sk4ZGwLt61w4aZhtOdmqIJUj1fNCxo6721F0pfg==",
      "docusign=53e074c1-b80d-41a1-be73-d444698c3a91",
      "docusign=12a35007-299f-4d83-bd45-4f1963b4e234",
      "canva-site-verification=mQci1SnoC4Y-iJQpirTu6Q",
      "cisco-ci-domain-verification=4b0af123fd61d9b672e3d23654d753d00150aec9b4c32ff0673f0f1b7801edab",
      "smartsheet-site-validation=o821NYtWlw35E2By_1h2gMDN-nAgTRqB",
      "atlassian-domain-verification=5lqJwtfJPMHqC/aGvT/7s2BR53IHCs9P6vFjCQYA5nkQ4mvoHKTqNTW7gucscGW7",
      "adobe-idp-site-verification=012b7d24aff9766444b9232173abb52ef026139e50aac77c49e02bd5d0dc3916",
      "jumpdesktop=12d076284350363e1df1806a94f0096dc18aed9d3a58a4e35376c09ce886",
      "anthropic-domain-verification-dfbjfj=cItiODp4D19q3YKkyJLoZsKXZ",
      "apple-domain-verification=pSxAase3tgjHfXBE",
      "google-site-verification=RcEUU_s2q7QWyysoeXd4Y0W3IE3QSpeu2lh2OFGRiJA",
      "Dynatrace-site-verification=f8c987df-9919-467d-80cf-05c74781a94e__j7ut0lc17ppaoqaqo4hm9dbq23",
      "MS=ms24761496",
      "google-site-verification=9KrlZfA2rYO7_JUgB6G6PzmIzp5C0aMcAgiODVFOXL4",
      "extensis-domain-verification=4dec3be6-1ab2-4cd3-b508-5a61c50ac453"
    ],
    "dmarc": [
      "v=DMARC1;p=none;fo=1;rua=mailto:Corp.Dmarc_RUA@disney.com;ruf=mailto:Corp.Dmarc_RUF@disney.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=watchdisneyfe.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Sep 21 00:00:00 2026 GMT",
    "notAfter": "Apr  6 23:59:59 2027 GMT",
    "san": [
      "watchdisneyfe.com",
      "*.abc.com",
      "freeform.com",
      "*.freeform.go.com",
      "*.fxtvfe.com",
      "*.abc-studios.com",
      "*.disneynow.com",
      "oscar.go.com",
      "*.abcstudios.go.com",
      "*.showms.freeform.go.com",
      "*.us-east-1.aws.hosted.watchdisneyfe.com",
      "fxnow.fxnetworks.com",
      "abcstudios.go.com",
      "fxtvfe.com",
      "latamtvfe.com",
      "*.oscar.go.com",
      "blackishtv.com",
      "*.ngtvfe.com",
      "*.marvel.com",
      "*.cdn.watchdisneyfe.com",
      "*.geo.hosted.watchdisneyfe.com",
      "freeform.go.com",
      "*.abc.go.com",
      "marvelfe.com",
      "marvel.com",
      "abc.go.com",
      "disneynow.com",
      "*.disneynow.go.com",
      "*.marvelfe.com",
      "*.watchdisneyfe.com",
      "abc.com",
      "fftvfe.com",
      "disneynow.go.com",
      "*.freeform.com",
      "abc-studios.com",
      "*.fftvfe.com",
      "*.latamtvfe.com",
      "*.blackishtv.com",
      "ngtvfe.com"
    ],
    "days_left": 193,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.121.28",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "ABC Network - ABC.com"
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [
    {}
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.abc.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://abc.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 43,
    "notable": [
      "api.abc.com",
      "api.partners.abc.com",
      "cdn.mktg.abc.com",
      "cdn.video.abc.com",
      "dev.cd.abc.com",
      "dev.galaxy.abc.com",
      "fcast.cdn.abc.com",
      "fcast.qa.cdn.abc.com",
      "help.abc.com",
      "ll.media.abc.com",
      "stage.cd.abc.com",
      "support.abc.com"
    ],
    "sample": [
      "a.abc.com",
      "abc.com",
      "api.abc.com",
      "api.partners.abc.com",
      "baton.mit.abc.com",
      "cdn.mktg.abc.com",
      "cdn.video.abc.com",
      "dev.cd.abc.com",
      "dev.galaxy.abc.com",
      "dwtsvote-live.abc.com",
      "dwtsvote-test.abc.com",
      "dwtsvote.abc.com",
      "emdesign-stage.net.abc.com",
      "emdesign.net.abc.com",
      "emindex.net.abc.com",
      "emindexdb.net.abc.com",
      "emsetup.net.abc.com",
      "emwebapps.net.abc.com",
      "fcast.cdn.abc.com",
      "fcast.qa.cdn.abc.com"
    ]
  },
  "elapsed_s": 126.5,
  "rechecked": "2026-09-25 10:43 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
