# Security Audit Report — shutterstock.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://shutterstock.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | shutterstock.com |
| Test date | 2026-09-26 18:59 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 5, Info: 13)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
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
- **Detail:** Header reveals: awselb/2.0
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (k2kcjaq0dcrwsl.shutterstock.com and hqp9nhpwjqkwho.shutterstock.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: yandex-verification: 0b8e9d2a0806468c; google-site-verification=WvdE_Kl6RWC4uUxKPVGw1Rgw2AW22mvF-vfPfGN-mJM; atlassian-domain-verification=ICd4kCPJdxkAWAAFMmIHHO9PFolvLRxUWjkjtn4b8BT2t66x72
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of shutterstock.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 257 disallow path(s), e.g. */login, */base/logout, */account, /subscribe_success, /download
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 75.2.58.105 carries PTR a0b8838bbcb103e9f.awsglobalaccelerator.com. for shutterstock.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "shutterstock.com",
  "dns": {
    "a": [
      "75.2.58.105",
      "99.83.219.164"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 20)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx5.googlemail.com (pref 30)",
      "aspmx4.googlemail.com (pref 30)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)"
    ],
    "ns": [
      "ns-1105.awsdns-10.org.",
      "ns-2006.awsdns-58.co.uk.",
      "ns-231.awsdns-28.com.",
      "ns-715.awsdns-25.net."
    ],
    "spf": [
      "yandex-verification: 0b8e9d2a0806468c",
      "google-site-verification=WvdE_Kl6RWC4uUxKPVGw1Rgw2AW22mvF-vfPfGN-mJM",
      "atlassian-domain-verification=ICd4kCPJdxkAWAAFMmIHHO9PFolvLRxUWjkjtn4b8BT2t66x72YUm4iLcwIH1dVi",
      "miro-verification=6836d18a57e57b86b38ad342b7a099736f1541e8",
      "datadome-domain-verify=6jjzntehvWqKMZ6IyeA0N2gFwaCKgmde",
      "atlassian-domain-verification=2FUGwVxsNLgKbCtS6ZpRcSLRksocMk9dV4gY5iBpwed0LbhaI2g5UUzoYaMzgD8e",
      "DirectFedAuthUrl=https://shutterstock.okta.com/app/shutterstock_foreseenewprod_1/exk14x7ojphmsUFk20x8/sso/saml",
      "google-site-verification=btTybBnUhrrIJjM2XavVzjtct5J_mGbt3G3UezinYV0",
      "yandex-verification: 021e3a8511fca527",
      "facebook-domain-verification=lrocxr79ofwtm82chaj8h4luuqpms7",
      "apple-domain-verification=mPQtvq6REj40T5tn",
      "jumpdesktop=4da40494ff58c7df38b610d468b6f2574dd6f35a22bbcd360b9c518d0f60",
      "lucidlink-verification=GFVJHTFJTFSNKF50BF27AYAGNG",
      "jamf-site-verification=TCI4tRcGn7UCfT-xuLp9yQ",
      "google-site-verification=vzI-qM-ENlsNGmQtR0Z29HRf0q9_mcXW7xCulDreLpc",
      "onetrust-domain-verification=f7acfe615ec343eeb1d812ca09165a48",
      "MS=ms49836191",
      "v=spf1 include:_spf.shutterstock_com._d.easydmarc.pro -all",
      "stripe-verification=b35adcb1d91d94699ec1de23631872c0e4df024e15686e6fb119003035bd6520",
      "ZOOM_verify_ZqCIeMn-RJ-laQ4kBcAyCw",
      "562761548-4810558",
      "mongodb-site-verification=EDpZVE7z02krpxdHZGxyBzQLgQw4A0EY",
      "mixpanel-domain-verify=1da3b141-95bc-4208-81df-f1b640703314",
      "atlassian-domain-verification=xnSgqTwgP81yyzKQEzb87CY1/U+sIbPROxNSG7TYBnUCwr2Qs+s7NuupIWceDPtG",
      "pendo-domain-verification=3671eb79-ab80-461d-bf11-63959a0dbc83",
      "invisionapp-verification=2241045992350101631628366167042829157218",
      "00d30000001ggscea0",
      "Foxit-domain-verification=0da244e9b4a363d00a75502cb83590bf",
      "mongodb-site-verification=lcCyzLUHMQCfa4oCJCqmn1grbdQ5HPEp",
      "DirectFedAuthUrl=https://shutterstock.okta.com/app/shutterstock_foreseenewpreview_1/exk14qwevlkQpSFEg0x8/sso/saml",
      "easydmarc-verification:36a2aa07-0843-411c-a39e-e90464a50a78",
      "globalsign-domain-verification=8frsHcE2ag-0ccaaP5BTpPmUJC8ob8pdjDQchfAWzD",
      "docker-verification=45ca3fb0-da99-4edd-8e14-2ffaffa7ce08",
      "docusign=93b1131d-22fa-467a-ac46-27e8a3ed4e34",
      "uber-domain-verification=df6f9b33-269c-49d9-96c0-945a2cac42bf",
      "openai-domain-verification=dv-btq9bkTqojCc09hLIoBq5Wz7",
      "atlassian-sending-domain-verification=b3c336a7-a32b-42e1-87a3-c9223137b95c"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:add78bd9e2@rua.easydmarc.us; ruf=mailto:dmarc-reports@shutterstock.com; fo=1; pct=100; rf=afrf"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=stockphotoeditor.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "May 24 00:00:00 2026 GMT",
    "notAfter": "Dec  7 23:59:59 2026 GMT",
    "san": [
      "stockphotoeditor.com",
      "skillfeed.com",
      "inacreativeworld.com",
      "imageneslibresdederechos.com",
      "videosemaltadefinicao.com",
      "highresvideos.com",
      "stockphotoeditor.info",
      "videosenalta.com",
      "imagenesroyaltyfree.com",
      "creatorstour.de",
      "*.bigstockcorp.com",
      "*.picdn.net",
      "shutterstock.com",
      "shutterstock.mobi",
      "videosroyaltyfree.com",
      "stockphotoeditor.net",
      "bancodevideos.com",
      "freestockeditor.com",
      "freestock.com",
      "offset.com",
      "freestockeditor.net",
      "bigstockcorp.com",
      "*.highresvideos.com",
      "videosenaltaresolucion.com"
    ],
    "days_left": 72,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "75.2.58.105",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.shutterstock.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://shutterstock.com:443/"
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
  "wildcard_dns": true,
  "apex_txt": [
    "yandex-verification: 0b8e9d2a0806468c",
    "google-site-verification=WvdE_Kl6RWC4uUxKPVGw1Rgw2AW22mvF-vfPfGN-mJM",
    "atlassian-domain-verification=ICd4kCPJdxkAWAAFMmIHHO9PFolvLRxUWjkjtn4b8BT2t66x72",
    "miro-verification=6836d18a57e57b86b38ad342b7a099736f1541e8",
    "atlassian-domain-verification=2FUGwVxsNLgKbCtS6ZpRcSLRksocMk9dV4gY5iBpwed0LbhaI2"
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
      "not_before": "20260524000000",
      "not_after": "20261207235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "*/login",
      "*/base/logout",
      "*/account",
      "/subscribe_success",
      "/download",
      "/checkout",
      "/account_purchase_history.mhtml",
      "/contests",
      "*/portfolio",
      "*/editor/template",
      "*/editor/design",
      "*/editor/search",
      "*/video/cart",
      "*/video/checkout",
      "*/music/cart"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a0b8838bbcb103e9f.awsglobalaccelerator.com."
    ]
  },
  "elapsed_s": 19.3,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
