# Security Audit Report — xbox.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://xbox.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | xbox.com |
| Test date | 2026-09-26 17:55 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

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
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | CT1 | 450 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 18 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Kestrel
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
- **Detail:** Header reveals: Kestrel
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=jRoICv0mMREqo5IthM1McDzE_8rRtEYtSVtHmOTUoJA; google-site-verification=e70dJcpsqnXzda_PC9I_VO_bpU9hlMlqhtvsxegHEQc; facebook-domain-verification=n2md3enk4k9r4s6kylpqmekhxyyrq7
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of xbox.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but xbox.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 9 disallow path(s), e.g. /error, /*Search?q*, /*search?q*, /*results?k*, /*Results?k*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] 450 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: americas.test.play.xbox.com, assets.play.xbox.com, auth.cert.xbox.com, auth.int2.xbox.com, auth.part.xbox.com, auth.xbox.com, beta.support-preview.ci.xbox.com, beta.support-preview.nightly.xbox.com, beta.support-preview.staging.xbox.com, beta.support-preview.xbox.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 18. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: auth.cert.xbox.com, auth.part.xbox.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "xbox.com",
  "dns": {
    "a": [
      "20.70.246.20",
      "20.231.239.246",
      "20.112.250.133",
      "20.236.44.162",
      "20.76.201.171"
    ],
    "aaaa": [
      "2603:1030:c02:8::14",
      "2603:1020:201:10::10f",
      "2603:1030:20e:3::23c",
      "2603:1030:b:3::152",
      "2603:1010:3:3::5b"
    ],
    "cname": null,
    "mx": [
      "xbox-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns2-205.azure-dns.net.",
      "ns4-205.azure-dns.info.",
      "ns1-205.azure-dns.com.",
      "ns3-205.azure-dns.org."
    ],
    "spf": [
      "google-site-verification=jRoICv0mMREqo5IthM1McDzE_8rRtEYtSVtHmOTUoJA",
      "b1939PPDAGDjXs+54riWGyuzfCM+s+PE66uPOHEQ+9z264YnfenE2CVrUxq+5UGTDqiOU8JqZ5AKRvfcUVpfXQ==",
      "google-site-verification=e70dJcpsqnXzda_PC9I_VO_bpU9hlMlqhtvsxegHEQc",
      "facebook-domain-verification=n2md3enk4k9r4s6kylpqmekhxyyrq7",
      "v=spf1 ip4:65.55.42.0/24 ip4:65.55.76.0/24 mx:xbox.com include:_spf-ssg-a.microsoft.com include:spf.protection.outlook.com -all",
      "facebook-domain-verification=yvcz1zil7qv3biswf68ikkxkh1nsoh",
      "docusign=c2837ae3-ac1e-446d-b257-c2328dce901a",
      "adobe-idp-site-verification=8aa35c528af5d72beb19b1bd3ed9b86d87ea7f24b2ba3c99ffcd00c27e9d809c",
      "atlassian-domain-verification=xvoaqRfxSg3PnlVnR4xCSOlKyw1Aln0MMxRiKXnwWroFG7vI76TUC8xYb03MwMXv",
      "AFDVALIDATION=Xbox"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:rua@dmarc.microsoft; ruf=mailto:ruf@dmarc.microsoft; fo=1:s:d"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=WA, localityName=Redmond, organizationName=Microsoft Corporation, commonName=surface.com",
    "issuer": "countryName=US, organizationName=Microsoft Corporation, commonName=Microsoft TLS G2 RSA CA OCSP 02",
    "notBefore": "Sep 17 11:37:30 2026 GMT",
    "notAfter": "Dec 26 10:37:30 2026 GMT",
    "san": [
      "myservice.surface.com",
      "xbox.com",
      "myservice.xbox.com",
      "microsoft.cz",
      "www.microsoft.cz",
      "www.winhec.net",
      "www.winhec.com",
      "winhec.net",
      "winhec.com",
      "microsoft.eu",
      "www.microsoft.eu",
      "windows.com",
      "www.gigjam.com",
      "gigjam.com",
      "microsoft.az",
      "microsoft.be",
      "microsoft.by",
      "microsoft.ca",
      "microsoft.ch",
      "microsoft.cl",
      "microsoft.dk",
      "microsoft.ee",
      "microsoft.es",
      "microsoft.fi",
      "microsoft.ge",
      "microsoft.hu",
      "microsoft.is",
      "microsoft.it",
      "microsoft.jp",
      "microsoft.lt",
      "microsoft.lu",
      "microsoft.lv",
      "microsoft.md",
      "microsoft.pl",
      "microsoft.pt",
      "microsoft.ro",
      "microsoft.rs",
      "microsoft.ru",
      "microsoft.se",
      "microsoft.si",
      "microsoft.tv",
      "microsoft.ua",
      "microsoft.uz",
      "microsoft.vn",
      "microsoft.cat",
      "imaginecup.pl",
      "windows.nl",
      "hololens.com",
      "microsoftedge.com",
      "windowsmarketplace.com",
      "microsoftcloud.com",
      "surface.com",
      "msdn.com",
      "www.msdn.com",
      "it.windows.com",
      "www.windows.nl",
      "www.surface.com",
      "www.windows.com",
      "explore.live.com",
      "www.hololens.com",
      "www.microsoft.ca",
      "www.microsoft.it",
      "www.microsoft.jp",
      "www.microsoft.pl",
      "www.microsoft.ru",
      "feedback.msdn.com",
      "itpro.windows.com",
      "www.imaginecup.pl",
      "dev.microsoftedge.com",
      "www.microsoftedge.com",
      "blog.microsoftedge.com",
      "bugs.microsoftedge.com",
      "data.microsoftedge.com",
      "www.microsoftcloud.com",
      "hardwaredev.windows.com",
      "issues.microsoftedge.com",
      "status.microsoftedge.com",
      "www.windowsmarketplace.com",
      "changelog.microsoftedge.com",
      "testdrive.microsoftedge.com",
      "mnc.ms",
      "gears.gg",
      "nuget.ms",
      "skype.tv",
      "mmynte.es",
      "ratify.sh",
      "mhybrid.cz",
      "rnmst1.com",
      "www.mnc.ms",
      "425show.dev",
      "ambetion.be",
      "codeplex.ru",
      "d365iom.com",
      "dugodaj.com",
      "maquette.ms",
      "olxwiki.com",
      "toycorp.org",
      "blog.dot.net",
      "bogdanss.com",
      "codeplex.com",
      "codeplex.net",
      "codeplex.org",
      "dynamics.com",
      "eenvoudig.nu",
      "fluentui.dev",
      "gearspop.com",
      "www.gears.gg",
      "www.nuget.ms",
      "www.skype.tv",
      "bellavite.org",
      "blogs.dot.net",
      "csshybrid.com",
      "demoaccsm.com",
      "gotcosmos.com",
      "msgamedev.com",
      "msgamedev.net",
      "msgamedev.org",
      "www.mmynte.es",
      "containers.dev",
      "www.fluentui.dev",
      "msftgamedev.com",
      "qiralliance.com",
      "qiralliance.org",
      "www.425show.dev",
      "www.ambetion.be",
      "www.codeplex.ru",
      "www.dugodaj.com",
      "www.maquette.ms",
      "www.olxwiki.com",
      "www.remix3d.com",
      "ambetion.digital",
      "contextualiq.com",
      "cssmigration.com",
      "dallasdragon.com",
      "dallasdragon.org",
      "qir-alliance.com",
      "qir-alliance.org",
      "www.eenvoudig.nu",
      "www.gearspop.com",
      "azurecosmosdb.com",
      "cupposunshine.com",
      "exchangehybrid.in",
      "www.msgamedev.com",
      "www.msgamedev.net",
      "www.msgamedev.org",
      "blog.azuremaps.com",
      "businesscentral.dk",
      "digitalambetion.be",
      "digitalambition.be",
      "docs.azuremaps.com",
      "dotnetpodcasts.com",
      "exchangehybrid.com",
      "surfacepreskoly.sk",
      "typescriptlang.org",
      "www.pandoralabs.pt",
      "digitalambetion.com",
      "live.gearsofwar.com",
      "msgamedeveloper.com",
      "www.msftgamedev.com",
      "archive.codeplex.com",
      "azurecontainerapp.io",
      "cloudchampions11.com",
      "microsoftfederal.com",
      "microsoftgamedev.com",
      "vanguardoutrider.com",
      "windowscontinuum.com",
      "www.ambetion.digital",
      "www.contextualiq.com",
      "www.dallasdragon.com",
      "www.dallasdragon.org",
      "azurecontainerapp.com",
      "azurecontainerapp.dev",
      "azurecontainerapp.net",
      "azurecontainerapps.io",
      "msftgamedeveloper.com",
      "msgamedevelopment.com",
      "updates.azuremaps.com",
      "vivaonboardingapp.dev",
      "azurecontainerapps.dev",
      "windowsuglysweater.com",
      "www.businesscentral.dk",
      "www.digitalambetion.be",
      "www.digitalambition.be",
      "gearstactics.com",
      "www.gearstactics.com",
      "gears5.com",
      "www.gears5.com",
      "natick.research.microsoft.com",
      "triviaforyou.net",
      "www.triviaforyou.net",
      "seeyouinthework.com",
      "www.seeyouinthework.com",
      "aieconomy.microsoft.com"
    ],
    "days_left": 90,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "20.70.246.20",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Kestrel"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.xbox.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.xbox.com/"
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
    "source": "crt.sh",
    "count": 450,
    "notable": [
      "americas.test.play.xbox.com",
      "assets.play.xbox.com",
      "auth.cert.xbox.com",
      "auth.int2.xbox.com",
      "auth.part.xbox.com",
      "auth.xbox.com",
      "beta.support-preview.ci.xbox.com",
      "beta.support-preview.nightly.xbox.com",
      "beta.support-preview.staging.xbox.com",
      "beta.support-preview.xbox.com",
      "beta.support.ci.xbox.com",
      "beta.support.nightly.xbox.com",
      "beta.support.xbox.com",
      "cdn.e.xbox.com",
      "checkout.xboxdesignlab.xbox.com"
    ],
    "sample": [
      "aad-xbox.s2s.onerf.xbox.com",
      "aad.ambassadorsadmin.xbox.com",
      "account-flighting-int.xbox.com",
      "account-flighting-ppe.xbox.com",
      "account-flighting-prod.xbox.com",
      "account-onerf.ppe.xbox.com",
      "account-origin.xbox.com",
      "account-preview.xbox.com",
      "account.xbox.com",
      "activity.ventura.ppe.xbox.com",
      "activity.ventura.xbox.com",
      "admin-xcl-preview.xbox.com",
      "admin-xcl.xbox.com",
      "agentservice.xbox.com",
      "agenttools.xbox.com",
      "alerts.xbox.com",
      "amashop-stage.xbox.com",
      "amashop-stage2.xbox.com",
      "ambassadors-origin.xbox.com",
      "ambassadors-preview.xbox.com"
    ],
    "dangling": [
      "auth.cert.xbox.com",
      "auth.part.xbox.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=jRoICv0mMREqo5IthM1McDzE_8rRtEYtSVtHmOTUoJA",
    "google-site-verification=e70dJcpsqnXzda_PC9I_VO_bpU9hlMlqhtvsxegHEQc",
    "facebook-domain-verification=n2md3enk4k9r4s6kylpqmekhxyyrq7",
    "facebook-domain-verification=yvcz1zil7qv3biswf68ikkxkh1nsoh",
    "adobe-idp-site-verification=8aa35c528af5d72beb19b1bd3ed9b86d87ea7f24b2ba3c99ffcd"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.12",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/error",
      "/*Search?q*",
      "/*search?q*",
      "/*results?k*",
      "/*Results?k*",
      "/_layouts/",
      "/_vti_bin/",
      "/*/contact-us?isChatCallAvailable=false",
      "/*/play/user/*"
    ]
  },
  "elapsed_s": 18.5,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
