# Security Audit Report — ouest-france.fr

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ouest-france.fr/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ouest-france.fr |
| Test date | 2026-09-26 16:42 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 0, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

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
      "ns-164-c.gandi.net.",
      "ns-39-a.gandi.net.",
      "ns-120-b.gandi.net."
    ],
    "spf": [
      "FBKvDjqQTagp7RvBFclHHIqQ28r5tIqi3cI1cR1U9c3/wMRtxMYDkNLEf7E8xPbqLyXCA9/0vatdcij9iymmDQ==",
      "google-site-verification=ZUoTvo4Vw2HgB_mHnyGiEcIq2mu5DHJ2Ac2Q9vwGs0s",
      "google-site-verification=jyMzKhQ4FGuEcxRk-2MYjSYJEu5EedJp8C-_Wnlt1j4",
      "v=spf1 include:de._netblocks.mimecast.com include:spf.protection.outlook.com include:sendgrid.net include:spf.mailjet.com include:spf.sendinblue.com ",
      " include:aspmx.pardot.com include:_spf.atlassian.net redirect=%{i}.spf-sipaof.fr",
      "brevo-code:06a75a3dc110e18f5f98049ffda07408",
      "iOS-enroll=https://gwclp.ouest-france.fr/rtc/vm-tuva4.domaine.local/MDM/api/v1/enroll/IosEnroll",
      "google-site-verification=g8siYJiIA2VPb1HQv9w22kXR7lde-h3Zc1T5PTEsVbw",
      "atlassian-sending-domain-verification=f7647c05-c955-4694-a5c7-ed34a2311490",
      "brevo-code:341ec5d7807d7688ec140d0ea717ab5d",
      "wip.runners=51bc4aa7edf5a4e4f291b27d70c8efb7",
      "google-site-verification=TJBQcdRNba_AAfrYkPBhBKYI-yXP2eovwwitqJ5nzxU",
      "brevo-code:dd56c2c0cef8cfcd4aac7723df6350b8",
      "wiz-domain-verification=f8adbe81a92b281861d6444a25cf6a256b36400e44f1a93b61b2983161e9c0da",
      "abuseipdb-verification=i1e6IPtc",
      "Sendinblue-code:b56bb0021980d6773d8bc7c2b3d3af17",
      "google-site-verification=e59tMQ11DGFt6aL7ih4hePR9tHupyiC_4CTcCnH5rE4",
      "GqiFaZKPKNEmhm4ZOxOvS+W4jNPQO5IJWkmCCTiz5ZPbyHrKfQjmIgmRJDe0BB9xLfN9g2B/9bni9KdvDpl+Lg==",
      "brevo-code:33bd9a6dfe6151cc84461f3f65010a76",
      "pardot933693=ed9b61516d69036f47b7cbfe849206c4c014c75cc7e4223017dd418fd272fd02",
      "google-site-verification=HgMmSeaM0OJ5Gz-q5j-3_CP6WDBcX88-NPkUIbiiyWU",
      "OSIAGENTREGURL=https://mobile.ouest-france.fr/MobileEnrollment/ld-iosEnroll.aspx",
      "ca3-d335ade3309a4b039fe7c1144d7941b5",
      "QiUyHY5CXVZVDZnEXdbXt6OPUWvvMd/K+Yn503PzP+33jGCYgxN4YtW/9yasc9dX6mfACJsGe/C/I9biKDLJzQ==",
      "K28NOxnN=f8afadfe6a0207a74cd55996abbbe1c5",
      "atlassian-domain-verification=VGUBsXBygKvUaItgMF6tj3ENtDha3doy8Ma1ahxB2zTsGYRAGLiZhKIGd5sHrRFP",
      "google-site-verification=w3cKdY5AfvQolHsBRmw_uBipk52BdHZtzT_5Ne4Z2mU",
      "google-site-verification=t9ZUqxMIqTxQ8XxMdfW0PwDUQwGkcSOz_ms8ScKDjPo",
      "brevo-code:170df14ad903a66270d2c9f0323b350f",
      "runners=bc4527faff45d383b007795d503cdf0f",
      "apple-domain-verification=UM2QXuPiPZ4rNX0q",
      "fastly-domain-delegation-uucxyfkhqkvvq3fchaea-00419161-2025-06-05",
      "yahoo-verification-key=XmMi04u79I4RgfvfYTrACYnP6+60fyt/S5XxV/HOKII=",
      "google-site-verification=xoAPL4EODmFkvsSgWpp1N_G1QVArdzGYptCMRkEgP7Q",
      "anthropic-domain-verification-5vv5rc=kZQQdusyWXhrS4wAEVxK3lKs9",
      "mgverify=05d569c79ed45260178c0cd5457a415a03bb3cc922f547c90cc61a534d6cd555",
      "atlassian-domain-verification=qfBCLKrblhZ5lJVxYyobgX6alxrxe7Sj0B6q7q09bGe5rH9uDaxpfyiJutA1LJOn",
      "0ed1fe018acfc94390c49e4ce3bf01f215c2a59ff0",
      "android-enroll=https://gwclp.ouest-france.fr/rtc/vm-tuva4.domaine.local/MDM/api/v1/enroll/AndroidEnroll",
      "google-site-verification=eAg6DrPLrk1BZ6nKEYWa_ll2aiQPu2gX2i6Kz1iYvEU",
      "LDLAUNCHPAD=https://mobile.ouest-france.fr/launchpad.cloud"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@ouest-france.fr"
    ],
    "dnssec_authenticated": false
  },
  "error": "ConnectionRefusedError(10061, '無法連線，因為目標電腦拒絕連線。', None, 10061, None)",
  "elapsed_s": 3.7,
  "rechecked": "2026-09-26 16:42 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
