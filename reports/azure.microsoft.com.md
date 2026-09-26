# Security Audit Report — azure.microsoft.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://azure.microsoft.com/ |
| Bug bounty program | Microsoft Online Services |
| Listed scope domain | azure.microsoft.com |
| Test date | 2026-09-25 08:40 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 1, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | CT1 | 31 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 3 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] 31 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: aef-alt.onedscollector.dev.azure.microsoft.com, aef.onedscollector.dev.azure.microsoft.com, assessment.changeguard.fcm.azure.microsoft.com, azure.microsoft.com, azurelocalsolutions.azure.microsoft.com, azurestackhcisolutions.azure.microsoft.com, changeexplorer.fcm.azure.microsoft.com, changeguard.fcm.azure.microsoft.com, emails-ppe.azure.microsoft.com, emails.azure.microsoft.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 3. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: aef-alt.onedscollector.dev.azure.microsoft.com, aef.onedscollector.dev.azure.microsoft.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "azure.microsoft.com",
  "dns": {
    "a": [
      "23.209.218.179"
    ],
    "aaaa": [
      "2600:1417:76:480::439b",
      "2600:1417:76:4a1::439b"
    ],
    "cname": "azure.microsoft.com.edgekey.net.",
    "mx": [],
    "ns": [],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=WA, localityName=Redmond, organizationName=Microsoft Corporation, commonName=azure.microsoft.com",
    "issuer": "countryName=US, organizationName=Microsoft Corporation, commonName=Microsoft TLS G2 RSA CA OCSP 04",
    "notBefore": "Sep 16 19:05:38 2026 GMT",
    "notAfter": "Apr  2 19:05:38 2027 GMT",
    "san": [
      "dialtone.azure.microsoft.com",
      "azure.microsoft.com"
    ],
    "days_left": 189,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.209.218.179",
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
    "status": 301,
    "location": "http://azure.microsoft.com/en-us"
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "source": "certspotter",
    "count": 31,
    "notable": [
      "aef-alt.onedscollector.dev.azure.microsoft.com",
      "aef.onedscollector.dev.azure.microsoft.com",
      "assessment.changeguard.fcm.azure.microsoft.com",
      "azure.microsoft.com",
      "azurelocalsolutions.azure.microsoft.com",
      "azurestackhcisolutions.azure.microsoft.com",
      "changeexplorer.fcm.azure.microsoft.com",
      "changeguard.fcm.azure.microsoft.com",
      "emails-ppe.azure.microsoft.com",
      "emails.azure.microsoft.com",
      "eu-aef.onedscollector.dev.azure.microsoft.com",
      "eu-kar.onedscollector.dev.azure.microsoft.com",
      "eu-uda.onedscollector.dev.azure.microsoft.com",
      "hcicatalog.azure.microsoft.com",
      "jwcc.azure.microsoft.com"
    ],
    "sample": [
      "aef-alt.onedscollector.dev.azure.microsoft.com",
      "aef.onedscollector.dev.azure.microsoft.com",
      "assessment.changeguard.fcm.azure.microsoft.com",
      "azure.microsoft.com",
      "azurelocalsolutions.azure.microsoft.com",
      "azurestackhcisolutions.azure.microsoft.com",
      "changeexplorer.fcm.azure.microsoft.com",
      "changeguard.fcm.azure.microsoft.com",
      "emails-ppe.azure.microsoft.com",
      "emails.azure.microsoft.com",
      "eu-aef.onedscollector.dev.azure.microsoft.com",
      "eu-kar.onedscollector.dev.azure.microsoft.com",
      "eu-uda.onedscollector.dev.azure.microsoft.com",
      "hcicatalog.azure.microsoft.com",
      "jwcc.azure.microsoft.com",
      "kar-alt.onedscollector.dev.azure.microsoft.com",
      "kar.onedscollector.dev.azure.microsoft.com",
      "portal-staging.changeguard.fcm.azure.microsoft.com",
      "portal-staging.changemanager.fcm.azure.microsoft.com",
      "portal.changeguard.fcm.azure.microsoft.com"
    ],
    "dangling": [
      "aef-alt.onedscollector.dev.azure.microsoft.com",
      "aef.onedscollector.dev.azure.microsoft.com"
    ]
  },
  "elapsed_s": 187.3,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
