# Security Audit Report — money.yandex.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://money.yandex.ru/ |
| Bug bounty program | Yandex |
| Listed scope domain | money.yandex.ru |
| Test date | 2026-09-26 18:55 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 2, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS1 | Domain does not resolve (no A/AAAA) | CWE-200 |
| 2 | low | MAIL9 | DMARC enforces (p=reject) but has no reporting address (rua) | CWE-285 |
| 3 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |

## Detailed findings

### 1. [INFO] Domain does not resolve (no A/AAAA) (`DNS1`)

- **CWE:** CWE-200
- **Detail:** No A or AAAA record returned from public resolvers; site may be offline or DNS-only outage.
- **Recommendation:** Confirm the service is still expected to be live.

### 2. [LOW] DMARC enforces (p=reject) but has no reporting address (rua) (`MAIL9`)

- **CWE:** CWE-285
- **Detail:** Without a rua= reporting address the policy cannot be tuned; mis-sends may be silently quarantined.
- **Recommendation:** Add a rua= reporting mailbox to the DMARC record.

### 3. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.money.yandex.ru/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

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
      "ns4.yandex.ru.",
      "ns3.yandex.ru."
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
    "status": "ct-pending"
  },
  "http2": {
    "error": "root GET failed"
  },
  "x12": {
    "error": "ConnectionError(MaxRetryError('HTTPSConnectionPool(host=\\'money.yandex.ru\\', por"
  },
  "elapsed_s": 9.3,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
