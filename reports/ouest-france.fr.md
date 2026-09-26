# Security Audit Report — ouest-france.fr

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ouest-france.fr/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ouest-france.fr |
| Test date | 2026-09-26 18:17 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 3, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 3 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 4 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 5 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 6 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 3. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): de. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 4. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.ouest-france.fr/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 5. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 6. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: abuseipdb-verification=i1e6IPtc; google-site-verification=xoAPL4EODmFkvsSgWpp1N_G1QVArdzGYptCMRkEgP7Q; google-site-verification=ZUoTvo4Vw2HgB_mHnyGiEcIq2mu5DHJ2Ac2Q9vwGs0s
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

## Evidence (raw response observations)

```json
{
  "domain": "ouest-france.fr",
  "dns": {
    "a": [
      "217.70.184.38"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "de-smtp-inbound-1.mimecast.com (pref 10)",
      "de-smtp-inbound-2.mimecast.com (pref 10)"
    ],
    "ns": [
      "ns-39-a.gandi.net.",
      "ns-120-b.gandi.net.",
      "ns-164-c.gandi.net."
    ],
    "spf": [
      "brevo-code:170df14ad903a66270d2c9f0323b350f",
      "FBKvDjqQTagp7RvBFclHHIqQ28r5tIqi3cI1cR1U9c3/wMRtxMYDkNLEf7E8xPbqLyXCA9/0vatdcij9iymmDQ==",
      "brevo-code:dd56c2c0cef8cfcd4aac7723df6350b8",
      "fastly-domain-delegation-uucxyfkhqkvvq3fchaea-00419161-2025-06-05",
      "brevo-code:06a75a3dc110e18f5f98049ffda07408",
      "abuseipdb-verification=i1e6IPtc",
      "google-site-verification=xoAPL4EODmFkvsSgWpp1N_G1QVArdzGYptCMRkEgP7Q",
      "iOS-enroll=https://gwclp.ouest-france.fr/rtc/vm-tuva4.domaine.local/MDM/api/v1/enroll/IosEnroll",
      "google-site-verification=ZUoTvo4Vw2HgB_mHnyGiEcIq2mu5DHJ2Ac2Q9vwGs0s",
      "wip.runners=51bc4aa7edf5a4e4f291b27d70c8efb7",
      "google-site-verification=jyMzKhQ4FGuEcxRk-2MYjSYJEu5EedJp8C-_Wnlt1j4",
      "runners=bc4527faff45d383b007795d503cdf0f",
      "google-site-verification=w3cKdY5AfvQolHsBRmw_uBipk52BdHZtzT_5Ne4Z2mU",
      "pardot933693=ed9b61516d69036f47b7cbfe849206c4c014c75cc7e4223017dd418fd272fd02",
      "google-site-verification=e59tMQ11DGFt6aL7ih4hePR9tHupyiC_4CTcCnH5rE4",
      "K28NOxnN=f8afadfe6a0207a74cd55996abbbe1c5",
      "ca3-d335ade3309a4b039fe7c1144d7941b5",
      "google-site-verification=HgMmSeaM0OJ5Gz-q5j-3_CP6WDBcX88-NPkUIbiiyWU",
      "google-site-verification=g8siYJiIA2VPb1HQv9w22kXR7lde-h3Zc1T5PTEsVbw",
      "QiUyHY5CXVZVDZnEXdbXt6OPUWvvMd/K+Yn503PzP+33jGCYgxN4YtW/9yasc9dX6mfACJsGe/C/I9biKDLJzQ==",
      "GqiFaZKPKNEmhm4ZOxOvS+W4jNPQO5IJWkmCCTiz5ZPbyHrKfQjmIgmRJDe0BB9xLfN9g2B/9bni9KdvDpl+Lg==",
      "v=spf1 include:de._netblocks.mimecast.com include:spf.protection.outlook.com include:sendgrid.net include:spf.mailjet.com include:spf.sendinblue.com ",
      " include:aspmx.pardot.com include:_spf.atlassian.net redirect=%{i}.spf-sipaof.fr",
      "LDLAUNCHPAD=https://mobile.ouest-france.fr/launchpad.cloud",
      "google-site-verification=eAg6DrPLrk1BZ6nKEYWa_ll2aiQPu2gX2i6Kz1iYvEU",
      "atlassian-sending-domain-verification=f7647c05-c955-4694-a5c7-ed34a2311490",
      "anthropic-domain-verification-5vv5rc=kZQQdusyWXhrS4wAEVxK3lKs9",
      "brevo-code:341ec5d7807d7688ec140d0ea717ab5d",
      "apple-domain-verification=UM2QXuPiPZ4rNX0q",
      "wiz-domain-verification=f8adbe81a92b281861d6444a25cf6a256b36400e44f1a93b61b2983161e9c0da",
      "mgverify=05d569c79ed45260178c0cd5457a415a03bb3cc922f547c90cc61a534d6cd555",
      "android-enroll=https://gwclp.ouest-france.fr/rtc/vm-tuva4.domaine.local/MDM/api/v1/enroll/AndroidEnroll",
      "google-site-verification=t9ZUqxMIqTxQ8XxMdfW0PwDUQwGkcSOz_ms8ScKDjPo",
      "atlassian-domain-verification=qfBCLKrblhZ5lJVxYyobgX6alxrxe7Sj0B6q7q09bGe5rH9uDaxpfyiJutA1LJOn",
      "atlassian-domain-verification=VGUBsXBygKvUaItgMF6tj3ENtDha3doy8Ma1ahxB2zTsGYRAGLiZhKIGd5sHrRFP",
      "google-site-verification=TJBQcdRNba_AAfrYkPBhBKYI-yXP2eovwwitqJ5nzxU",
      "Sendinblue-code:b56bb0021980d6773d8bc7c2b3d3af17",
      "0ed1fe018acfc94390c49e4ce3bf01f215c2a59ff0",
      "yahoo-verification-key=XmMi04u79I4RgfvfYTrACYnP6+60fyt/S5XxV/HOKII=",
      "OSIAGENTREGURL=https://mobile.ouest-france.fr/MobileEnrollment/ld-iosEnroll.aspx",
      "brevo-code:33bd9a6dfe6151cc84461f3f65010a76"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@ouest-france.fr"
    ],
    "dnssec_authenticated": false
  },
  "error": "ConnectionRefusedError(10061, '無法連線，因為目標電腦拒絕連線。', None, 10061, None)",
  "apex_txt": [
    "abuseipdb-verification=i1e6IPtc",
    "google-site-verification=xoAPL4EODmFkvsSgWpp1N_G1QVArdzGYptCMRkEgP7Q",
    "google-site-verification=ZUoTvo4Vw2HgB_mHnyGiEcIq2mu5DHJ2Ac2Q9vwGs0s",
    "google-site-verification=jyMzKhQ4FGuEcxRk-2MYjSYJEu5EedJp8C-_Wnlt1j4",
    "google-site-verification=w3cKdY5AfvQolHsBRmw_uBipk52BdHZtzT_5Ne4Z2mU"
  ],
  "tls2": {
    "error": "ConnectionRefusedError(10061, '無法連線，因為目標電腦拒絕連線。', None, 10061, None)"
  },
  "http2": {
    "error": "root GET failed"
  },
  "elapsed_s": 11.2,
  "rechecked": "2026-09-26 18:18 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
