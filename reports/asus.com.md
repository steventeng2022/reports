# Security Audit Report — asus.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://asus.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | asus.com |
| Test date | 2026-09-25 08:37 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **4** (High: 0, Medium: 1, Low: 0, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | TLS1 | TLS certificate chain not trusted | CWE-298 |
| 3 | info | TLS9 | Neither TLS 1.2 nor 1.3 handshake succeeded | CWE-327 |
| 4 | info | CT1 | 118 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 4. [INFO] 118 hostnames found via Certificate Transparency (certspotter) (`CT1`)

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
      "mg1.asus.com (pref 20)",
      "mg2.asus.com (pref 100)",
      "mg.asus.com (pref 10)"
    ],
    "ns": [
      "ns-1875.awsdns-42.co.uk.",
      "ns-337.awsdns-42.com.",
      "ns-544.awsdns-04.net.",
      "ns-1039.awsdns-01.org."
    ],
    "spf": [
      "facebook-domain-verification=tkhj31qarb9901xcperg0w0yfcdazh",
      "google-site-verification=va5g5RuEWw-pwEJ7ssCrnyBAggf7yCLxugRggQY8Udc",
      "docusign=9c43421e-314b-49f7-82ae-fe698bce40bd",
      "google-site-verification=iA3Ko0FQtp-yaka9tibkFlF98ZMkxrnu5ofKd9QQ-QE",
      "mu56Kq__Cg9v_aczc5degR_4sMXtsDa2AeU3-oEsihw",
      "bv-domain-verification=e134f5546cb5c93ee5ffb1f47c8015873876076d9c43dda13d85dfc6341f65ca",
      "v=spf1 ip4:103.10.4.0/22 ip4:213.61.92.115 ip4:218.211.38.242 ip4:118.163.110.210 ip4:213.61.152.30 include:spf.protection.outlook.com -all",
      "MS=ms94547556",
      "google-site-verification=Rs_zuu4Gqxki8VVX5xNs63-tIOcut0qvdvYvW2KLY38",
      "zzldvfj08yfss0ydft85bbysmy1cj96x.",
      "trend-micro-v1-domain-verification.e5d263b0eb2014dbafc1625a7865e267=1ea4ccc7-05b5-476d-aff9-5272fc7c5d2e",
      "google-site-verification=44buYvNtZHvSRVcj2dOJGZMtmPAaLOa9zPSVMMVwbaY",
      "1dbc8bc7963d4b0e90bbb0e474e38e2e",
      "hT5pYl5FKR/fwLMKrJ1KQPnZrNC8YzgJ7REPX6Wux1cRehEIzwrOuyB9ASXckqMz+rHto/UaM/44UfPgbQFjYg==",
      "wiz-domain-verification=6e11efe846bf3a2f81870077d571d06c8650aff084bd960c34cfc32434dac695",
      "5YA7LJMOVXX399OL065GX65G87UKJ20FFDBUVX2M",
      "7894A73F0CFEDD51A6EA5C7E4CCD13A3965623132C7519E917382CF0131AA3F2",
      "google-site-verification=71RHI7e5zrzhwOgNIz8aT-pbh6LGw1zQ7VWTAnhlpF8",
      "docusign=f0d1ec0b-94f3-4abf-bf6f-e5c894776e57",
      "pardot922413=75629e802092cb0ac07329098a29b2cec1b3d86f4470d27f5643addd5bc78707",
      "atlassian-domain-verification=2Z9J5op7FAXNJxHd0AExZaq7IBe8R8DFbq6Lh6Qx/fhUeEWmSeGtuSYud7tFYjGn",
      "atlassian-domain-verification=jxVtO6D77cvTtzPiqZUe8DiTmI1mqdbU0jqM66bYHskWVDfx5kiqtfOWcKBZMAVC",
      "google-site-verification=ZAxDQWYWbQka8_PwpGcJnv38NFkB1kp4ZeamtqNEjLw",
      "google-site-verification=eUHxhIYbA4kM7heyt2W2onNhJHLTXuDgo4VE3snEBKw",
      "adobe-idp-site-verification=382f5b6399951cb3de1a5d1dbd06bb8eb8d701f88c4ea5db38aa69347dd9a13f",
      "apple-domain-verification=YVSgEqQtJRjmdVBu"
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
  "elapsed_s": 113.5,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
