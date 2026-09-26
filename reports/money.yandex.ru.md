# Security Audit Report — money.yandex.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://money.yandex.ru/ |
| Bug bounty program | Yandex |
| Listed scope domain | money.yandex.ru |
| Test date | 2026-09-25 10:02 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 0, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS1 | Domain does not resolve (no A/AAAA) | CWE-200 |

## Detailed findings

### 1. [INFO] Domain does not resolve (no A/AAAA) (`DNS1`)

- **CWE:** CWE-200
- **Detail:** No A or AAAA record returned from public resolvers; site may be offline or DNS-only outage.
- **Recommendation:** Confirm the service is still expected to be live.

## Evidence (raw response observations)

```json
{
  "domain": "money.yandex.ru",
  "dns": {
    "a": [],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx.yandex.ru (pref 0)"
    ],
    "ns": [
      "ns3.yandex.ru.",
      "ns4.yandex.ru."
    ],
    "spf": [
      "v=spf1 include:_spf-ipv4.yandex.ru include:_spf-ipv6.yandex.ru -all"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;"
    ]
  },
  "tls": {
    "status": "no-ip"
  },
  "ports": {
    "status": "no-ip"
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 20.1,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
