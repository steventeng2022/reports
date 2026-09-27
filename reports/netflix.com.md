# Security Audit Report — netflix.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://netflix.com/ |
| Bug bounty program | Netflix |
| Listed scope domain | netflix.com |
| Test date | 2026-09-27 02:38 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 4, Info: 17)

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
| 13 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 17 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 18 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 19 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |
| 20 | info | CT1 | 91 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 21 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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
- **Detail:** Apex TXT records with verification/token content: zapier-domain-verification-challenge=d740d03c-47a4-491c-934d-c61bdba6099e; freepik-domain-verification=eeb4ee5ff6237e57ea15d2369b574c68; deepl-domain-verification=f6610dd4c1414006bd6382c115542467
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but netflix.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 133 disallow path(s), e.g. /, /accountstatus, /AccountStatus, /aui/inbound, /authenticate
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 52.38.7.83 carries PTR ec2-52-38-7-83.us-west-2.compute.amazonaws.com. for netflix.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on netflix.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 17. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The netflix.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 18. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of netflix.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 19. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of netflix.com discloses a 1-hop fronting chain (1.1 i-0c77b1fcf06badbf7 (us-west-2)); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

### 20. [INFO] 91 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: ablaze.test.netflix.com, advertising.staging.netflix.com, cdn.nxtgms.netflix.com, cdn.sand.nxtgms.netflix.com, cdn.tech.nxtgms.netflix.com, cms.obiwan.stage.netflix.com, control.tls.develop.test.cloud.netflix.com, develop.staging.ssic.netflix.com, help.netflix.com, help.stage.netflix.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 21. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

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
      "2600:1f14:62a:de81:b848:82ee:2416:447e",
      "2600:1f14:62a:de80:69a8:7b12:8e5f:855d",
      "2600:1f14:62a:de82:822d:a423:9e4c:da8d"
    ],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "aspmx2.googlemail.com (pref 10)"
    ],
    "ns": [
      "ns-659.awsdns-18.net.",
      "ns-81.awsdns-10.com.",
      "ns-1984.awsdns-56.co.uk.",
      "ns-1372.awsdns-43.org."
    ],
    "caa": [
      "0 issue \"pki.goog\"",
      "0 issue \"digicert.com\"",
      "0 issue \"letsencrypt.org\""
    ],
    "spf": [
      "e6060ec6-b362-4acb-9a1f-b80e99d17753",
      "elevenlabs=yhxq_JyMuzy2_pQ5B-M4HJ8sZaFLLiQGelMOuBcTWE4",
      "zapier-domain-verification-challenge=d740d03c-47a4-491c-934d-c61bdba6099e",
      "asv=4853f01b1e9226ed9d0031284948059f",
      "freepik-domain-verification=eeb4ee5ff6237e57ea15d2369b574c68",
      "deepl-domain-verification=f6610dd4c1414006bd6382c115542467",
      "tiktok-domain-verification=e8242b26316716e951678da03b794de5a838482929d5b62ea2e0a3b4baf843f3",
      "5f5a7676-2a28-4400-a64e-465626e5ff6b",
      "google-site-verification=YVxAf7gFR4vFk1RkUwiYt3pzl2AVUP6aPdBgV1qtwcw",
      "notion-domain-verification=MHmHAv2mrRGxVuA3rhIRmz6vwrsAEbsqCR6yRIycSoj",
      "miro-verification=9ac407d6774b2ec4313b004d40204399e37f3b48",
      "lucidlink-verification=TZFHBCZT2MG33J59D4FB3W9EKG",
      "1password-site-verification=BXCRTZRWNVG4PFLIYFIBWSYHX4",
      "infoblox-domain-mastery=83433630723145c8e700674aa65ad12bf58d7cd22434a5527c383d131ccc354a77",
      "neat-pulse-domain-verification-6X6Z7kX=56aa4659-fdcc-42df-802e-f1cce082b1ea",
      "docusign=f3d36bef-ec7d-42e5-9334-626611acb127",
      "facebook-domain-verification=k65vedr09b2tp2q144ho1zewp3xsc6",
      "docker-verification=5f9a055c-22b9-4d40-be7f-5af4171e1e71",
      "unity-sso-verification=46eb4cbd-e316-4691-84c2-4f4bce784d84",
      "anthropic-domain-verification-vxqysx=XDtJHKRTpvy6QvuMuyVMXbMxT",
      "google-site-verification=nCi1QdlMabPJOvtQNCo5KaPyDfwog9pDr3d8IN767YA",
      "luma-ai-domain-verification-340eet=BLdaj62h2qtpk2yvLLYFNuMA9",
      "appspace-domain-verification=59cd40985507690b0ac0e2c83d24dd6dfa24c7d7571f00b7401e01d5c12332af",
      "klaviyo-site-verification=WwbqJa",
      "docusign=f249396f-8150-48f8-8bd2-705be6e03826",
      "lucidlink-verification=8XRGA7HR9S7XZ469MR70GSABB0",
      "h1-domain-verification=AYCqXFtcqVzAhHLWr58GvY2WrbTfkGeMsijza2jPS2E1qcn1",
      "atlassian-domain-verification=TX0Efjn8bXAu0o9GAHyYowM0mcu4oDPHFf10cqaDXFCvU9tRB7R/A9oeQcDmEAD8",
      "8cd468d7d5994fcc9d350683a8cb07a1",
      "loom-verification=0004053852",
      "google-site-verification=VQKoV3pv-QYIDfbQa1N4r97x8W07veRTK6JhWUavIuc",
      "logmein-verification-code=4FVB4FQ17eVMyHCC7RAApS4Zp",
      "logmein-verification-code=905b1ed4-1c2e-466f-b24c-756e6ca39eb5",
      "lucidlink-verification=GSM5VV6S2T2DZADV5JM8WPBYZM",
      "google-site-verification=a8Lak2UwVjIlmH1xRYU3mJ6nSQ7rJnyf2VKWtH4nKZI",
      "google-site-verification=9DgwSKXMlFzcnW-HuGWef6aVVHWDCQNehxHTq0Ps9IA",
      "v=spf1 include:_spf_ipv4.netflix.com include:_spf.google.com include:amazonses.com include:servers.mcsv.net include:_spf.salesforce.com include:_spf.createsend.com -all",
      "sso-domain-verification-7wfrk6=LfxRM5a023zTb2jO6QWeDcZ9e",
      "google-site-verification=Wn4h4x_Gf8Zs5qiw88ZingFRjLUNzga-zJXts2UPics",
      "smartsheet-site-validation=zZPtdlBFlbl-n54tmRUUcd6Bd8lllpAR",
      "dropbox-domain-verification=htwo11xk2yl1",
      "lucidlink-verification=BC5DTMP5YWAJHDNPRF5ASW8QA0",
      "canva-site-verification=DW6T-OKEapKu9QB9ChMocw",
      "apple-domain-verification=U1j_Aj0pS5fid78Cag85YGM14jHrzxM-S2ICXc8rGxg",
      "google-site-verification=F6fRKDfeR1Uqz8qJvmH3HmQQxpu9JYY9GJUFeV3hU3Y",
      "jamf-site-verification=vqjVdHx1f_q52DK-WclChA",
      "bluebeam-verification=ivn6qi30eug84iz4njykvb8jenp2wm",
      "klaviyo-site-verification=UM4UEX",
      "apple-domain-verification=Ohlo8qLyb9N4JaIm"
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
    "days_left": 144,
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
    "zapier-domain-verification-challenge=d740d03c-47a4-491c-934d-c61bdba6099e",
    "freepik-domain-verification=eeb4ee5ff6237e57ea15d2369b574c68",
    "deepl-domain-verification=f6610dd4c1414006bd6382c115542467",
    "tiktok-domain-verification=e8242b26316716e951678da03b794de5a838482929d5b62ea2e0a",
    "google-site-verification=YVxAf7gFR4vFk1RkUwiYt3pzl2AVUP6aPdBgV1qtwcw"
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
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 7571332614918275581228228424345088683,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
        "http://crl4.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl"
      ],
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
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e696131123010060355040713094c6f73204761746f733110300e060355040a13074e6574666c6978311830160603550403130f7777772e6e6574666c69782e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473320544c532045434320534841333834203230323020434131",
      "not_before": "20260218000000",
      "not_after": "20270218214148"
    },
    "ocsp": "explicit-status"
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
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-52-38-7-83.us-west-2.compute.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.netflix.com/",
    "http_status": 301,
    "p404_status": 301,
    "wellknown": [
      "/.well-known/assetlinks.json"
    ],
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=31536000; includeSubDomains",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "x17": {
    "ocsp_http": "http://ocsp.digicert.com",
    "via": "1.1 i-0c77b1fcf06badbf7 (us-west-2)"
  },
  "elapsed_s": 37.0,
  "rechecked": "2026-09-27 02:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- re-run #15 passive additions: TLS 1.0/1.1, cipher-suite and key-exchange observations come from the handshake the base TLS check already performed plus one quiet re-handshake with no HTTP traffic; HTML-level angles read the root document already fetched for header checks; the only extra request this pass is a read-only GET to /.well-known/openid-configuration (plus the earlier passes' security.txt, sitemap.xml and CRL GETs).
- re-run #16 passive additions: the edge/protocol angles read the alt-svc, server-timing and CDN-identification headers from the one root GET; the preconnect/dns-prefetch, base-href and noindex angles parse the already-fetched root document; the TLS 1.2-only ceiling, SHA-1 signature and weak-key angles use the certificate evidence the base TLS check already captured; the only extra requests this pass are two read-only GETs (/.well-known/jwks.json and /.well-known/change-password).
- re-run #17 passive additions: the retired-header angles (Public-Key-Pins, Expect-CT, X-Permitted-Cross-Domain-Policies, Via, COOP/COEP, Permissions-Policy) read from the one root GET; the wildcard SAN, http:// OCSP and 398-day-cap angles use the certificate evidence the base TLS check already captured (SAN now harvested from the existing DER); the only extra requests this pass are three read-only GETs (/.well-known/dpop-jwks.json, /.well-known/origin-rsa-keys.json, /.well-known/llms.txt).
- Findings are reported against the public program scope; submission through the program tracker is pending.
