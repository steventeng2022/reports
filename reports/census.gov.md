# Security Audit Report — census.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://census.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | census.gov |
| Test date | 2026-09-25 18:31 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **2** (High: 0, Medium: 0, Low: 0, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | CT1 | 139 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] 139 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: access.stage.census.gov, api.census.gov, api.embargo.census.gov, auth.census.gov, ca.apps.tco.census.gov, ca.e.apps.tco.census.gov, centurion.stage.census.gov, cidr.stage.econ.census.gov, darhts.dapps.dev.2026test.census.gov, darhts.dapps.stage.2026test.census.gov
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "census.gov",
  "dns": {
    "a": [
      "148.129.75.166"
    ],
    "aaaa": [
      "2610:20:2010:a05:1000:0:9481:4ba6"
    ],
    "cname": null,
    "mx": [
      "mail2.census.gov (pref 50)",
      "mail1.census.gov (pref 50)"
    ],
    "ns": [
      "ns1e.census.gov.",
      "ns2e.census.gov."
    ],
    "spf": [
      "infoblox-domain-mastery=578e129560f03adc81a7b3f658065459be516b52709d8fde2b1183b71db46b7e5c",
      "apple-domain-verification=2jIC5VNEsj8bPdnu",
      "+i27enlfMpLlk9UWn4Ku+sUy3QO5Lnbysj+2rdvlyfPtq28iCTuH3b9ZnVWcYbhtrY1f1H9xsXT74U75J6h2aQ==",
      "adobe-idp-site-verification=c75e766ae664774cb9d671205f69ba1bbb97fbacb49c55d78725c432ef88e31d",
      "google-site-verification=5gdefaxvKpVMBIGemF2Dw4yBrtDazSNnprwC3sLsrUE",
      "google-site-verification=KnpcXkPcji6vLLd7Scev-xZMllMdI8f75Ibi--S4lzI",
      "v=spf1 ip4:148.129.0.0/16 ip6:2610:20:2000:101::f:0 ip6:2610:20:2010:a04::f:0 mx include:csod.spf.census.gov include:i1.spf.census.gov include:i2.spf.census.gov ~all",
      "google-site-verification=OMpp6MyQ1bAbnGclpbKqCMZal_1HxJapzG2tSRWFbzI",
      "apple-domain-verification=A8NwvlnLg7Cm2H3G",
      "MS=ms38105103",
      "airtable-verification=3602865d8095935581ec510122a7f819"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@valigov.email,mailto:dmarc+rua@other.mail.census.gov,mailto:dmarc-reports@doc.gov,mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:dmarc+ruf@other.mail.census.gov; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "elapsed_s": 7.5,
  "rechecked": "2026-09-25 18:50 UTC",
  "tls_error": "TimeoutError('timed out')",
  "ports": {
    "ip": "148.129.75.166",
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
    "count": 139,
    "notable": [
      "access.stage.census.gov",
      "api.census.gov",
      "api.embargo.census.gov",
      "auth.census.gov",
      "ca.apps.tco.census.gov",
      "ca.e.apps.tco.census.gov",
      "centurion.stage.census.gov",
      "cidr.stage.econ.census.gov",
      "darhts.dapps.dev.2026test.census.gov",
      "darhts.dapps.stage.2026test.census.gov",
      "download.census.gov",
      "econ.test.census.gov",
      "ecorr.stage.it.census.gov",
      "ecorrfaq.stage.it.census.gov",
      "github.e.it.census.gov"
    ],
    "sample": [
      "access.stage.census.gov",
      "adfs.census.gov",
      "adsdbtrs01.adsd.census.gov",
      "adsdbtrs02.adsd.census.gov",
      "akamai-datastream.census.gov",
      "api.census.gov",
      "api.embargo.census.gov",
      "auth-aws-lab.census.gov",
      "auth-ite.census.gov",
      "auth.census.gov",
      "bcc-mail2.tco.census.gov",
      "bds.explorer.ces.census.gov",
      "bhs.econ.census.gov",
      "broadcast.census.gov",
      "business.census.gov",
      "businessknows.census.gov",
      "ca.apps.tco.census.gov",
      "ca.e.apps.tco.census.gov",
      "cat-dmz.econ.census.gov",
      "census.gov"
    ]
  }
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
