# Security Audit Report — asus.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://asus.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | asus.com |
| Test date | 2026-09-26 17:39 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 1, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | TLS1 | TLS certificate chain not trusted | CWE-298 |
| 3 | info | TLS9 | Neither TLS 1.2 nor 1.3 handshake succeeded | CWE-327 |
| 4 | low | MAIL9 | DMARC enforces (p=reject) but has no reporting address (rua) | CWE-285 |
| 5 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 6 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 7 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 8 | info | CT1 | 118 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [MEDIUM] TLS certificate chain not trusted (`TLS1`)

- **CWE:** CWE-298
- **Detail:** TLS verification failed: [WinError 10054] 遠端主機已強制關閉一個現存的連線。
- **Recommendation:** Fix the certificate chain (missing intermediate / issuer).

### 3. [INFO] Neither TLS 1.2 nor 1.3 handshake succeeded (`TLS9`)

- **CWE:** CWE-327
- **Detail:** Only legacy protocols (if any) could complete a handshake.
- **Recommendation:** Upgrade TLS configuration.

### 4. [LOW] DMARC enforces (p=reject) but has no reporting address (rua) (`MAIL9`)

- **CWE:** CWE-285
- **Detail:** Without a rua= reporting address the policy cannot be tuned; mis-sends may be silently quarantined.
- **Recommendation:** Add a rua= reporting mailbox to the DMARC record.

### 5. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 6. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 7. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=jxVtO6D77cvTtzPiqZUe8DiTmI1mqdbU0jqM66bYHskWVDfx5k; apple-domain-verification=YVSgEqQtJRjmdVBu; google-site-verification=71RHI7e5zrzhwOgNIz8aT-pbh6LGw1zQ7VWTAnhlpF8
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 8. [INFO] 118 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: idp.asus.com, oauth.asus.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "asus.com",
  "dns": {
    "a": [
      "103.10.4.227"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mg2.asus.com (pref 100)",
      "mg1.asus.com (pref 20)",
      "mg.asus.com (pref 10)"
    ],
    "ns": [
      "ns-1875.awsdns-42.co.uk.",
      "ns-337.awsdns-42.com.",
      "ns-544.awsdns-04.net.",
      "ns-1039.awsdns-01.org."
    ],
    "spf": [
      "atlassian-domain-verification=jxVtO6D77cvTtzPiqZUe8DiTmI1mqdbU0jqM66bYHskWVDfx5kiqtfOWcKBZMAVC",
      "hT5pYl5FKR/fwLMKrJ1KQPnZrNC8YzgJ7REPX6Wux1cRehEIzwrOuyB9ASXckqMz+rHto/UaM/44UfPgbQFjYg==",
      "apple-domain-verification=YVSgEqQtJRjmdVBu",
      "zzldvfj08yfss0ydft85bbysmy1cj96x.",
      "v=spf1 ip4:103.10.4.0/22 ip4:213.61.92.115 ip4:218.211.38.242 ip4:118.163.110.210 ip4:213.61.152.30 include:spf.protection.outlook.com -all",
      "google-site-verification=71RHI7e5zrzhwOgNIz8aT-pbh6LGw1zQ7VWTAnhlpF8",
      "google-site-verification=eUHxhIYbA4kM7heyt2W2onNhJHLTXuDgo4VE3snEBKw",
      "5YA7LJMOVXX399OL065GX65G87UKJ20FFDBUVX2M",
      "bv-domain-verification=e134f5546cb5c93ee5ffb1f47c8015873876076d9c43dda13d85dfc6341f65ca",
      "mu56Kq__Cg9v_aczc5degR_4sMXtsDa2AeU3-oEsihw",
      "atlassian-domain-verification=2Z9J5op7FAXNJxHd0AExZaq7IBe8R8DFbq6Lh6Qx/fhUeEWmSeGtuSYud7tFYjGn",
      "docusign=f0d1ec0b-94f3-4abf-bf6f-e5c894776e57",
      "adobe-idp-site-verification=382f5b6399951cb3de1a5d1dbd06bb8eb8d701f88c4ea5db38aa69347dd9a13f",
      "facebook-domain-verification=tkhj31qarb9901xcperg0w0yfcdazh",
      "pardot922413=75629e802092cb0ac07329098a29b2cec1b3d86f4470d27f5643addd5bc78707",
      "1dbc8bc7963d4b0e90bbb0e474e38e2e",
      "google-site-verification=44buYvNtZHvSRVcj2dOJGZMtmPAaLOa9zPSVMMVwbaY",
      "google-site-verification=va5g5RuEWw-pwEJ7ssCrnyBAggf7yCLxugRggQY8Udc",
      "7894A73F0CFEDD51A6EA5C7E4CCD13A3965623132C7519E917382CF0131AA3F2",
      "docusign=9c43421e-314b-49f7-82ae-fe698bce40bd",
      "google-site-verification=Rs_zuu4Gqxki8VVX5xNs63-tIOcut0qvdvYvW2KLY38",
      "google-site-verification=iA3Ko0FQtp-yaka9tibkFlF98ZMkxrnu5ofKd9QQ-QE",
      "wiz-domain-verification=6e11efe846bf3a2f81870077d571d06c8650aff084bd960c34cfc32434dac695",
      "trend-micro-v1-domain-verification.e5d263b0eb2014dbafc1625a7865e267=1ea4ccc7-05b5-476d-aff9-5272fc7c5d2e",
      "google-site-verification=ZAxDQWYWbQka8_PwpGcJnv38NFkB1kp4ZeamtqNEjLw",
      "MS=ms94547556"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; sp=quarantine"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "untrusted",
    "version": null,
    "cipher": null,
    "subject": null,
    "issuer": null,
    "notBefore": null,
    "notAfter": null,
    "san": null,
    "error": "[WinError 10054] 遠端主機已強制關閉一個現存的連線。",
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": false,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "103.10.4.227",
    "open": []
  },
  "https": {
    "status": 0,
    "content_type": "",
    "title": "",
    "error": "https connect failed"
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [],
  "http": {
    "status": 0,
    "error": "http connect failed"
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "source": "certspotter",
    "count": 118,
    "notable": [
      "idp.asus.com",
      "oauth.asus.com"
    ],
    "sample": [
      "acbz-vpn.asus.com",
      "account.asus.com",
      "aceleraconasus.asus.com",
      "acf-cdn-ai-market-analyst-api.asus.com",
      "acf-cdn-ai-market-analyst.asus.com",
      "acf-cdn-m.asus.com",
      "aci-cti.asus.com",
      "acss-uat.asus.com",
      "acss.asus.com",
      "adapter.asus.com",
      "ai-market-analyst-api.asus.com",
      "ai-market-analyst.asus.com",
      "airag.asus.com",
      "amaxcdntest.asus.com",
      "aocc-crawlerapi.asus.com",
      "api-proart.asus.com",
      "asuscontrolcenter.asus.com",
      "asusexam.asus.com",
      "asusfilemanager.asus.com",
      "candycloud.asus.com"
    ]
  },
  "apex_txt": [
    "atlassian-domain-verification=jxVtO6D77cvTtzPiqZUe8DiTmI1mqdbU0jqM66bYHskWVDfx5k",
    "apple-domain-verification=YVSgEqQtJRjmdVBu",
    "google-site-verification=71RHI7e5zrzhwOgNIz8aT-pbh6LGw1zQ7VWTAnhlpF8",
    "google-site-verification=eUHxhIYbA4kM7heyt2W2onNhJHLTXuDgo4VE3snEBKw",
    "bv-domain-verification=e134f5546cb5c93ee5ffb1f47c8015873876076d9c43dda13d85dfc63"
  ],
  "tls2": {
    "error": "ConnectionResetError(10054, '遠端主機已強制關閉一個現存的連線。', None, 10054, None)"
  },
  "http2": {
    "error": "root GET failed"
  },
  "elapsed_s": 34.2,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
