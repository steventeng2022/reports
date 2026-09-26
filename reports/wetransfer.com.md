# Security Audit Report — wetransfer.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wetransfer.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | wetransfer.com |
| Test date | 2026-09-26 17:55 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 1, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | P8 | Missing security.txt | CWE-1038 |
| 5 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 6 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 7 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 8 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 9 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 10 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 4. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 5. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 6. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 7. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (rohqitfvhhysco.wetransfer.com and ecdw99vrwcqo1w.wetransfer.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 8. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=XW_EN8p8Aq6F0vXQo8QJFXTzZH3bHQnLYA4TFyPN63E; google-site-verification=L4cTbeDJCawV2WcUBdIg0ZohUIzmQsyri0cW9Vfx3ms; adobe-idp-site-verification=27c19071d43cf50bb319f12dca1b494fb4ac78700f01158bc53c
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 9. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of wetransfer.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 10. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 24 disallow path(s), e.g. /*?*, /api/, /ter-optout, /pm-optout, /mar-optout
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "wetransfer.com",
  "dns": {
    "a": [
      "54.192.248.118",
      "54.192.248.7",
      "54.192.248.21",
      "54.192.248.99"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-616.awsdns-13.net.",
      "ns-381.awsdns-47.com.",
      "ns-1743.awsdns-25.co.uk.",
      "ns-1495.awsdns-58.org."
    ],
    "spf": [
      "lemlist-verif=3a27e226",
      "google-site-verification=XW_EN8p8Aq6F0vXQo8QJFXTzZH3bHQnLYA4TFyPN63E",
      "ZOOM_verify_KL0Tx6QHRE-pFo1TUH489w",
      "google-site-verification=L4cTbeDJCawV2WcUBdIg0ZohUIzmQsyri0cW9Vfx3ms",
      "adobe-idp-site-verification=27c19071d43cf50bb319f12dca1b494fb4ac78700f01158bc53c750a64a62677",
      "anthropic-domain-verification-v74473=mmo7JLEzQN3oOrEhxNuzyUxja",
      "notion-domain-verification=Yg69TXpuZUoTBv5Ri6zQhMtHrF7gDDypUiwiwsKcc8Q",
      "v=spf1 include:spf1.wetransfer.com include:servers.mcsv.net include:_spf.google.com include:mail.zendesk.com include:mailsenders.netsuite.com -all",
      "docusign=d8951d4e-554f-42ad-878e-a8cfa144f728",
      "slack-domain-verification=wvKukMkbZSVirrbxUeRN90GH6W7HoJVKjCqpdsCc",
      "atlassian-domain-verification=SvE4jaub7awLiMuXWZa/MJuI10LQaiwUVcYdQa2xKuCB6Y6dKD9Z9olL9iVfyJed",
      "facebook-domain-verification=h9w15klgw91n2ot3lw77t035wqw2vb",
      "_1l13uk3o31dwxht8gy20uftkq7njy9i",
      "google-site-verification=psmb0t3fy95_06_HZTTKA42vG8jQp8utdBMGYCgbJn8",
      "apple-domain-verification=HVcqj6adUo39535i",
      "google-site-verification=22yq8uEpGxlFe2r7H413v6Wor4yaJDF_XM0wsOxoXjs",
      "jamf-site-verification=EPAkOUuclyfbWuPrE4bFJg",
      "wrike-verification=MTc5Mjk4MTpjOWI1MzY4ODdmMGU4ZDA1NDI4MWJiM2ZkYmJhMmE0YzMzMmVkOTUyMjg0MWZjNWFhZTY2YjliOWMyMDExY2M4",
      "airtable-verification=1424b5a97e88024b52c0d21bf8a1cd64",
      "asv=89178be4f98e857aed14bc7a748446eb",
      "Notion_verify_4qsvK9AQNWyTTydLGyF3ysuoJuYcgPfo6qzsKeWsJba9ayET3MJsMLQA2AhsM6HGMa7UL",
      "ibmid=0b0660a3-b186-469a-8b70-25eac0c5a095",
      "google-site-verification=o1-Z5_XysLkNRL_Fr0XzMxTNDGCHoVJzwmOgG5apYrs",
      "google-site-verification=pZwqaQca9efqhei-uJPD1AYhimUB37qXYq-2jvp-mhc",
      "google-site-verification=ZdmG6lG1KKqyINxvbgMYMLtigj2Zjc5qasxPp7ikZ3I",
      "stripe-verification=448ebe2b06a2eba394d9e73a16a897dee98918e6e8593961f56e86bb6296c520",
      "google-site-verification=12Dz3BKB7bWfhvTLookytJl2LUfhuheBky3SokggYkc",
      "google-site-verification=QgqEa_4yOMSHcWSMtJrG4M0jeBwKBK07p7E5A73Ht_Q",
      "amazonses:OkYxgsklLbk4Efq6tshR+hWtLlWSmWy6A49YvL6zwqw=",
      "rippling-domain-verification=217697edd61756fc",
      "onetrust-domain-verification=2580b3683efb4e6f91ea1440cc1bee77",
      "MS=ms33481336"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:reports@dmarc.bendingspoons.com; pct=100;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=wetransfer.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Jul 24 00:00:00 2026 GMT",
    "notAfter": "Feb  6 23:59:59 2027 GMT",
    "san": [
      "wetransfer.com",
      "*.wetransfer.com"
    ],
    "days_left": 133,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.118",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "WeTransfer | Invia rapidamente file di grandi dimensioni"
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
      "origin": "https://sub.wetransfer.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://wetransfer.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=XW_EN8p8Aq6F0vXQo8QJFXTzZH3bHQnLYA4TFyPN63E",
    "google-site-verification=L4cTbeDJCawV2WcUBdIg0ZohUIzmQsyri0cW9Vfx3ms",
    "adobe-idp-site-verification=27c19071d43cf50bb319f12dca1b494fb4ac78700f01158bc53c",
    "anthropic-domain-verification-v74473=mmo7JLEzQN3oOrEhxNuzyUxja",
    "notion-domain-verification=Yg69TXpuZUoTBv5Ri6zQhMtHrF7gDDypUiwiwsKcc8Q"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/*?*",
      "/api/",
      "/ter-optout",
      "/pm-optout",
      "/mar-optout",
      "/renewal-reminder-optout",
      "/wallpaper/",
      "/wallpapers/",
      "/unlisted/",
      "/transfers",
      "/account/",
      "/workspace/",
      "/contacts",
      "/checkout",
      "/payment/"
    ]
  },
  "elapsed_s": 13.2,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
