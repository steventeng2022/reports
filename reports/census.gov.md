# Security Audit Report — census.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://census.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | census.gov |
| Test date | 2026-09-26 18:14 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 1, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 3 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 4 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 5 | info | CT1 | 139 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.census.gov/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 3. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 4. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=OMpp6MyQ1bAbnGclpbKqCMZal_1HxJapzG2tSRWFbzI; airtable-verification=3602865d8095935581ec510122a7f819; apple-domain-verification=A8NwvlnLg7Cm2H3G
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 5. [INFO] 139 hostnames found via Certificate Transparency (certspotter) (`CT1`)

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
      "mail1.census.gov (pref 50)",
      "mail2.census.gov (pref 50)"
    ],
    "ns": [
      "ns1e.census.gov.",
      "ns2e.census.gov."
    ],
    "spf": [
      "+i27enlfMpLlk9UWn4Ku+sUy3QO5Lnbysj+2rdvlyfPtq28iCTuH3b9ZnVWcYbhtrY1f1H9xsXT74U75J6h2aQ==",
      "google-site-verification=OMpp6MyQ1bAbnGclpbKqCMZal_1HxJapzG2tSRWFbzI",
      "airtable-verification=3602865d8095935581ec510122a7f819",
      "apple-domain-verification=A8NwvlnLg7Cm2H3G",
      "google-site-verification=KnpcXkPcji6vLLd7Scev-xZMllMdI8f75Ibi--S4lzI",
      "apple-domain-verification=2jIC5VNEsj8bPdnu",
      "infoblox-domain-mastery=578e129560f03adc81a7b3f658065459be516b52709d8fde2b1183b71db46b7e5c",
      "adobe-idp-site-verification=c75e766ae664774cb9d671205f69ba1bbb97fbacb49c55d78725c432ef88e31d",
      "MS=ms38105103",
      "google-site-verification=5gdefaxvKpVMBIGemF2Dw4yBrtDazSNnprwC3sLsrUE",
      "v=spf1 ip4:148.129.0.0/16 ip6:2610:20:2000:101::f:0 ip6:2610:20:2010:a04::f:0 mx include:csod.spf.census.gov include:i1.spf.census.gov include:i2.spf.census.gov ~all"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@valigov.email,mailto:dmarc+rua@other.mail.census.gov,mailto:dmarc-reports@doc.gov,mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:dmarc+ruf@other.mail.census.gov; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "error": "TimeoutError('timed out')",
  "apex_txt": [
    "google-site-verification=OMpp6MyQ1bAbnGclpbKqCMZal_1HxJapzG2tSRWFbzI",
    "airtable-verification=3602865d8095935581ec510122a7f819",
    "apple-domain-verification=A8NwvlnLg7Cm2H3G",
    "google-site-verification=KnpcXkPcji6vLLd7Scev-xZMllMdI8f75Ibi--S4lzI",
    "apple-domain-verification=2jIC5VNEsj8bPdnu"
  ],
  "tls2": {
    "error": "TimeoutError('timed out')"
  },
  "http2": {
    "error": "root GET failed"
  },
  "elapsed_s": 45.5,
  "rechecked": "2026-09-26 18:15 UTC",
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
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
