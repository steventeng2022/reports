# Security Audit Report — netflix.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://netflix.com/ |
| Bug bounty program | Netflix |
| Listed scope domain | netflix.com |
| Test date | 2026-09-26 17:49 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 9 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | CT1 | 91 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 17 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: envoy
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

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
- **Detail:** Header reveals: envoy
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'nfvdid' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 9. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'nfvdid' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.netflix.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: miro-verification=9ac407d6774b2ec4313b004d40204399e37f3b48; google-site-verification=nCi1QdlMabPJOvtQNCo5KaPyDfwog9pDr3d8IN767YA; google-site-verification=a8Lak2UwVjIlmH1xRYU3mJ6nSQ7rJnyf2VKWtH4nKZI
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of netflix.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but netflix.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 133 disallow path(s), e.g. /, /accountstatus, /AccountStatus, /aui/inbound, /authenticate
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] 91 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: ablaze.test.netflix.com, advertising.staging.netflix.com, cdn.nxtgms.netflix.com, cdn.sand.nxtgms.netflix.com, cdn.tech.nxtgms.netflix.com, cms.obiwan.stage.netflix.com, control.tls.develop.test.cloud.netflix.com, develop.staging.ssic.netflix.com, help.netflix.com, help.stage.netflix.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 17. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: cdn.nxtgms.netflix.com, cdn.sand.nxtgms.netflix.com, cdn.tech.nxtgms.netflix.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "netflix.com",
  "dns": {
    "a": [
      "52.38.7.83",
      "44.240.158.19",
      "44.242.13.161"
    ],
    "aaaa": [
      "2600:1f14:62a:de84:880a:88cc:a16:5423",
      "2600:1f14:62a:de85:d7:e7a1:8f7d:f6f5",
      "2600:1f14:62a:de83:c61a:d6e:18b0:65f7"
    ],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "aspmx3.googlemail.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-659.awsdns-18.net.",
      "ns-1984.awsdns-56.co.uk.",
      "ns-81.awsdns-10.com.",
      "ns-1372.awsdns-43.org."
    ],
    "spf": [
      "miro-verification=9ac407d6774b2ec4313b004d40204399e37f3b48",
      "google-site-verification=nCi1QdlMabPJOvtQNCo5KaPyDfwog9pDr3d8IN767YA",
      "asv=4853f01b1e9226ed9d0031284948059f",
      "google-site-verification=a8Lak2UwVjIlmH1xRYU3mJ6nSQ7rJnyf2VKWtH4nKZI",
      "docusign=f3d36bef-ec7d-42e5-9334-626611acb127",
      "apple-domain-verification=Ohlo8qLyb9N4JaIm",
      "apple-domain-verification=U1j_Aj0pS5fid78Cag85YGM14jHrzxM-S2ICXc8rGxg",
      "loom-verification=0004053852",
      "lucidlink-verification=TZFHBCZT2MG33J59D4FB3W9EKG",
      "klaviyo-site-verification=WwbqJa",
      "notion-domain-verification=MHmHAv2mrRGxVuA3rhIRmz6vwrsAEbsqCR6yRIycSoj",
      "8cd468d7d5994fcc9d350683a8cb07a1",
      "docusign=f249396f-8150-48f8-8bd2-705be6e03826",
      "atlassian-domain-verification=TX0Efjn8bXAu0o9GAHyYowM0mcu4oDPHFf10cqaDXFCvU9tRB7R/A9oeQcDmEAD8",
      "elevenlabs=yhxq_JyMuzy2_pQ5B-M4HJ8sZaFLLiQGelMOuBcTWE4",
      "infoblox-domain-mastery=83433630723145c8e700674aa65ad12bf58d7cd22434a5527c383d131ccc354a77",
      "google-site-verification=VQKoV3pv-QYIDfbQa1N4r97x8W07veRTK6JhWUavIuc",
      "appspace-domain-verification=59cd40985507690b0ac0e2c83d24dd6dfa24c7d7571f00b7401e01d5c12332af",
      "logmein-verification-code=905b1ed4-1c2e-466f-b24c-756e6ca39eb5",
      "anthropic-domain-verification-vxqysx=XDtJHKRTpvy6QvuMuyVMXbMxT",
      "facebook-domain-verification=k65vedr09b2tp2q144ho1zewp3xsc6",
      "smartsheet-site-validation=zZPtdlBFlbl-n54tmRUUcd6Bd8lllpAR",
      "jamf-site-verification=vqjVdHx1f_q52DK-WclChA",
      "1password-site-verification=BXCRTZRWNVG4PFLIYFIBWSYHX4",
      "bluebeam-verification=ivn6qi30eug84iz4njykvb8jenp2wm",
      "docker-verification=5f9a055c-22b9-4d40-be7f-5af4171e1e71",
      "logmein-verification-code=4FVB4FQ17eVMyHCC7RAApS4Zp",
      "lucidlink-verification=8XRGA7HR9S7XZ469MR70GSABB0",
      "google-site-verification=9DgwSKXMlFzcnW-HuGWef6aVVHWDCQNehxHTq0Ps9IA",
      "deepl-domain-verification=f6610dd4c1414006bd6382c115542467",
      "dropbox-domain-verification=htwo11xk2yl1",
      "lucidlink-verification=GSM5VV6S2T2DZADV5JM8WPBYZM",
      "tiktok-domain-verification=e8242b26316716e951678da03b794de5a838482929d5b62ea2e0a3b4baf843f3",
      "google-site-verification=F6fRKDfeR1Uqz8qJvmH3HmQQxpu9JYY9GJUFeV3hU3Y",
      "klaviyo-site-verification=UM4UEX",
      "zapier-domain-verification-challenge=d740d03c-47a4-491c-934d-c61bdba6099e",
      "unity-sso-verification=46eb4cbd-e316-4691-84c2-4f4bce784d84",
      "google-site-verification=Wn4h4x_Gf8Zs5qiw88ZingFRjLUNzga-zJXts2UPics",
      "freepik-domain-verification=eeb4ee5ff6237e57ea15d2369b574c68",
      "luma-ai-domain-verification-340eet=BLdaj62h2qtpk2yvLLYFNuMA9",
      "5f5a7676-2a28-4400-a64e-465626e5ff6b",
      "sso-domain-verification-7wfrk6=LfxRM5a023zTb2jO6QWeDcZ9e",
      "neat-pulse-domain-verification-6X6Z7kX=56aa4659-fdcc-42df-802e-f1cce082b1ea",
      "e6060ec6-b362-4acb-9a1f-b80e99d17753",
      "google-site-verification=YVxAf7gFR4vFk1RkUwiYt3pzl2AVUP6aPdBgV1qtwcw",
      "v=spf1 include:_spf_ipv4.netflix.com include:_spf.google.com include:amazonses.com include:servers.mcsv.net include:_spf.salesforce.com include:_spf.createsend.com -all",
      "canva-site-verification=DW6T-OKEapKu9QB9ChMocw",
      "lucidlink-verification=BC5DTMP5YWAJHDNPRF5ASW8QA0",
      "h1-domain-verification=AYCqXFtcqVzAhHLWr58GvY2WrbTfkGeMsijza2jPS2E1qcn1"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:netflix@rua.netcraft.com,mailto:dmarcreports@netflix.com,mailto:dmarc_agg@dmarc.250ok.net;ruf=mailto:netflix@ruf.netcraft.com,mailto:dmarcreports@netflix.com,mailto:dmarc_fr@dmarc.250ok.net"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Los Gatos, organizationName=Netflix, commonName=www.netflix.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Feb 18 00:00:00 2026 GMT",
    "notAfter": "Feb 18 21:41:48 2027 GMT",
    "san": [
      "account.netflix.com",
      "ca.netflix.com",
      "develop-stage.netflix.com",
      "embed.develop-stage.netflix.com",
      "embed.release-stage.netflix.com",
      "netflix.ca",
      "netflix.com",
      "release-stage.netflix.com",
      "signup.netflix.com",
      "tv.netflix.com",
      "www.netflix.ca",
      "www.netflix.com",
      "www1.netflix.com",
      "www2.netflix.com",
      "www3.netflix.com"
    ],
    "days_left": 145,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "52.38.7.83",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: envoy"
  ],
  "cookies": [
    {
      "domain": ".netflix.com"
    },
    {
      "domain": ".netflix.com",
      "samesite": "strict"
    },
    {
      "domain": ".netflix.com",
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.netflix.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://netflix.com/"
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
    "source": "certspotter",
    "count": 91,
    "notable": [
      "ablaze.test.netflix.com",
      "advertising.staging.netflix.com",
      "cdn.nxtgms.netflix.com",
      "cdn.sand.nxtgms.netflix.com",
      "cdn.tech.nxtgms.netflix.com",
      "cms.obiwan.stage.netflix.com",
      "control.tls.develop.test.cloud.netflix.com",
      "develop.staging.ssic.netflix.com",
      "help.netflix.com",
      "help.stage.netflix.com",
      "ichnaea.staging.netflix.com",
      "jira.corp.netflix.com",
      "jira.netflix.com",
      "logs.staging.netflix.com",
      "nm.push.sandbox.netflix.com"
    ],
    "sample": [
      "ablaze.test.netflix.com",
      "account.leportal.netflix.com",
      "acct-api.netflix.com",
      "advertising.staging.netflix.com",
      "android-appboot-staging.netflix.com",
      "billdesk-sihub-encryption.netflix.com",
      "billdesk-sihub-signature-prod.netflix.com",
      "c00.nxtgms.netflix.com",
      "c00.sand.nxtgms.netflix.com",
      "c00.tech.nxtgms.netflix.com",
      "c01.nxtgms.netflix.com",
      "c01.sand.nxtgms.netflix.com",
      "c01.tech.nxtgms.netflix.com",
      "c02.nxtgms.netflix.com",
      "c02.sand.nxtgms.netflix.com",
      "c02.tech.nxtgms.netflix.com",
      "cast.netflix.com",
      "cdn.nxtgms.netflix.com",
      "cdn.sand.nxtgms.netflix.com",
      "cdn.tech.nxtgms.netflix.com"
    ],
    "dangling": [
      "cdn.nxtgms.netflix.com",
      "cdn.sand.nxtgms.netflix.com",
      "cdn.tech.nxtgms.netflix.com"
    ]
  },
  "apex_txt": [
    "miro-verification=9ac407d6774b2ec4313b004d40204399e37f3b48",
    "google-site-verification=nCi1QdlMabPJOvtQNCo5KaPyDfwog9pDr3d8IN767YA",
    "google-site-verification=a8Lak2UwVjIlmH1xRYU3mJ6nSQ7rJnyf2VKWtH4nKZI",
    "apple-domain-verification=Ohlo8qLyb9N4JaIm",
    "apple-domain-verification=U1j_Aj0pS5fid78Cag85YGM14jHrzxM-S2ICXc8rGxg"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/accountstatus",
      "/AccountStatus",
      "/aui/inbound",
      "/authenticate",
      "/autologin",
      "/clearcookies",
      "/companies",
      "/editpayment",
      "/emailunsubscribe",
      "/error",
      "/eula",
      "/geooverride",
      "/help",
      "/imagelibrary"
    ]
  },
  "elapsed_s": 22.7,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
