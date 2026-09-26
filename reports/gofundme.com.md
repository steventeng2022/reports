# Security Audit Report — gofundme.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gofundme.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | gofundme.com |
| Test date | 2026-09-25 17:52 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 4, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 11 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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

### 10. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'gdid' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 11. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'gdid' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "gofundme.com",
  "dns": {
    "a": [
      "54.192.248.33",
      "54.192.248.37",
      "54.192.248.78",
      "54.192.248.43"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 10)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx5.googlemail.com (pref 30)",
      "aspmx4.googlemail.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "ns-1860.awsdns-40.co.uk.",
      "ns-1148.awsdns-15.org.",
      "ns-279.awsdns-34.com.",
      "ns-1018.awsdns-63.net."
    ],
    "spf": [
      "D24pYKS_dVZOjQrnXT0sZd8wICnikg",
      "ZOOM_verify_uRWfBI2AbJeSqiNLFUItq5",
      "pinterest-site-verification=b367ddd575e4643b2ac5fefbb3bf84c6",
      "_globalsign-domain-verification=MK_ZKmss4D_DdzGOsssHxxBOK6hJc6LGycFvNOESdZ",
      "knqas9grs1e90id70n6qtblc6s",
      "canva-site-verification=IqTb0UBeilINf10w5raSTQ",
      "atlassian-domain-verification=pDoSyXtzAVxSEb/lQ90Pfrgh87LFeL3vh9cAmjYGXaONtLKtJzDxfD2ARw8sqn/i",
      "anthropic-domain-verification-t4e4qe=Q1VWFhuqdtNXUmkvbvPe0aNCH",
      "onetrust-domain-verification=ae6ed1d46523448a905b9d8781b1f2d9",
      "google-site-verification=3LLkSZCqjHLPPrJiZMqE6AUja9L69F0ogae8o7JU6x4",
      "openai-domain-verification=dv-QetyqJL9vMGOTwGXZe04zDzf",
      "onetrust-domain-verification=6311c78fff614a938475a7085108477b",
      "docusign=852fdcf3-d757-4993-acd7-50a6a836365f",
      "docker-verification=f1a95df7-225d-4b44-a5d5-852c4e55539f",
      "v=spf1 include:gofundme.com._nspf.vali.email  include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:mail.zendesk.com include:servers.mcsv.net include:emailus.freshservice.com include:docebosaas.com include:sparkpostmail.com ~all",
      "maestro-cloud-domain-verification-8sf8ap=UAP61AxkIXLrtLqM3DPIjAOP3",
      "adobe-idp-site-verification=b23a174f3ecb4906444742af94b4c61d1948b6ba9665d33d2127abbac4e4bb6a",
      "google-site-verification=NtmRkQwVZHP-qs02vSRFkLA3Wn8xmi93HEEJsIpQaWU",
      "linear-domain-verification=fdr7mty4ieug",
      "loom-site-verification=2d2eebdbc4004cba854c231b81ddbc37",
      "hubspot-domain-verification=OWZlYTIzYmQtNjhlMi00MmU4LWI0NWEtYjE4NGM2MDFiZjdl",
      "rippling-domain-verification=40df0889be186979",
      "google-site-verification=J5wipyL1r3azHeawGlORXWlBscqyoYTcQpvlSeldLdQ",
      "google-site-verification=yTucH5oN_CeaxxpMntyk_jYQMtGyAv8W6rPZjHdXwIA",
      "google-site-verification=1VNhR6mITAZOOgVYtcdutrYdASgKtAnRITXKBQH6N3o",
      "globalsign-domain-verification=wvdz6fqNpGYoUxoyCbEUOYrkz-Z8Nh2zXAoS8lsLRh",
      "facebook-domain-verification=stk03ifpht9yaex2dibsxivrr9yor2",
      "google-site-verification=PVGZ_SowsyCYImkZyR7BWQAf0xBoWeUIuQ-9zwwio2s",
      "google-site-verification=lWd6YulLrAH6-0uZ5AX-P5-VcxTnfjF2aQ9Ey7lK96o",
      "google-site-verification=qYAWkOCPaLxMmYxSW2YahQ4GG4la3a9hNWFhDJcd2r4",
      "stripe-verification=7e70d91b569f8a0590a7b1b4c2933dade452811dee08d86cfce9ea1db35bff14",
      "google-site-verification=Lj3x8aEMLy8y3btjGcK48UpZsOJobv1zIFdK6lDzLMY",
      "MS=ms75016599",
      "48BCBFD65C",
      "google-site-verification=MyZCdkOIehJ00yJgtChbK4geHjxlUnuSGXwBI4n73xs",
      "apple-domain-verification=VWhGR6I4xDAzdl50",
      "mgverify=fdcb133238019c86b951dbb58430f60163ad2967fa91a367a65ea9a4edcf538e",
      "google-site-verification=uvhS3R59UN5exwoSVEi9oFgrQtcrDlWYQMcWRVe5S68",
      "_wpengine-sso-challenge=3Bj5M7GKohpXqt6K7ufz30hQAMH",
      "zapier-domain-verification-challenge=822070a7-9aa6-45fc-a3fa-d67b2dbc6c23",
      "twilio-domain-verification=0fbe678874c1832be4b21e661c491ee6",
      "google-site-verification=cZ9Hawb_wfuisC8fkQbwE1v8bjFJ0cf2bepzKRFDsXQ",
      "google-site-verification=9J3ulCSuevKr0hSdxoSmyccnjKgO1Qk_h55qjGJWMdk",
      "gamma-domain-verification-g2tf71=XUfSVhJFiN82HacNFl6iLBfvZ",
      "google-site-verification=O7naSlyLdrJJfCqA4ktOYCn9vrudsbppXY8j0EvSbC0",
      "google-site-verification=-97-MskUtq0BKfJ4HGBHfGDbU2XBfza9wf9pUk_3aWs"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@vali.email,mailto:sre+valiagg@gofundme.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.gofundme.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jul 26 00:00:00 2026 GMT",
    "notAfter": "Feb  8 23:59:59 2027 GMT",
    "san": [
      "*.gofundme.com",
      "gofundme.com"
    ],
    "days_left": 136,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.33",
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
  "cookies": [
    {
      "domain": "gofundme.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.gofundme.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://gofundme.com:443/"
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
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 502,
    "/.htaccess": 502,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 10.8,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
