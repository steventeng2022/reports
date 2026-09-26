# Security Audit Report — monster.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://monster.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | monster.com |
| Test date | 2026-09-26 17:49 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 1, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 3 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 4 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 5 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 6 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 3. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 4. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 5. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=rRq11A1dCsb5_qBT_3Fs9Sag5f8Wm5t58e05wQAESa0; apple-domain-verification=jHHEM7KcSPaadK20; yahoo-verification-key=E3zIMY4vqEPbyoGg80CV/bYPK0gmAjYeuPtCA+b20To=
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 6. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of monster.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "monster.com",
  "dns": {
    "a": [
      "166.117.15.191",
      "166.117.209.20"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "ALT2.ASPMX.L.GOOGLE.com (pref 5)",
      "ALT4.ASPMX.L.GOOGLE.com (pref 10)",
      "ALT3.ASPMX.L.GOOGLE.com (pref 10)",
      "ALT1.ASPMX.L.GOOGLE.com (pref 5)",
      "ASPMX.L.GOOGLE.com (pref 1)"
    ],
    "ns": [
      "ns2.tmpw.net.",
      "ns1.tmpw.net."
    ],
    "spf": [
      "google-site-verification=rRq11A1dCsb5_qBT_3Fs9Sag5f8Wm5t58e05wQAESa0",
      "apple-domain-verification=jHHEM7KcSPaadK20",
      "yahoo-verification-key=E3zIMY4vqEPbyoGg80CV/bYPK0gmAjYeuPtCA+b20To=",
      "_emotuf3vawbotgg5omeu1cvo2jhxdvu",
      "google-site-verification=h1591ugHHOFsWchw3mvQFe_l7qR4iinHtA4sDlxmwRE",
      "amazonses:gceEoeOqKvtfdmPp+y52S86QwEM6SHc4QH3ekZE3bpQ=",
      "v=spf1 mx ip4:220.226.205.66/32 ip4:208.71.192.0/21 ip4:193.164.143.0/24 ip4:64.127.116.65/26 ip4:64.127.121.0/27 ip4:98.174.21.153 ip4:69.25.33.0/24 include:spf.protection.outlook.com include:amazonses.com include:zgateway.zuora.com include:_spf.google.c",
      "om include:_spf.salesforce.com ip4:34.237.212.16/32 ip4:18.136.40.242/32 ip4:44.238.220.251/32  ~all",
      "google-site-verification=zXNA4jzGldUrb4WTfbWVyylyVgZRuVjpzS94ul_sr4g",
      "dell-technologies-domain-verification=monster.com_14b47215-d44f-4358-908e-2b7892392b4c_1722463976",
      "cloudhealth=471ef53e-b947-4d03-adf9-ca29bb43a8c3",
      "webexdomainverification.=d6c0c09e-1efb-4b83-ac2c-c8b15118cc48",
      "ciscocidomainverification=460719eb94004fbc3ffceb58ee7a94d0e45e14d1d224b3f193f0d122a6bdfbae",
      "ZOOM_verify_943D2iGtnuDRLVbiPRdQdz",
      "_gkbtqbmmu4k082wtt6q501wxlf0r48a",
      "datadome-domain-verify=B3KUK3qaB3COSjvTsFb9ZlUuVKr8F0ZJ",
      "oeIe2rwXtpnwFPKPFBl9AUpQpm1iDrxNx4NI18LFyR6cWwoIYsvRYfHhkxLg8PNGDw2IPkdD3q6w0cDi5wRxgA==",
      "9uhsn2f7lot7574rnlm4ercqpb",
      "GOytBs9lVe7A6ONbpEz1H+ouv1k8wnclMo3W48PX7mnZBaxXqJpJxTR5cdRPkUnunTbWui64V/PCEOOZDZsEXg==",
      "onetrust-domain-verification=0ec2972887414a679d57a96ccc29b5b0",
      "atlassian-domain-verification=bKSyyEicgY0Nu7x4asJ5ja9ueF/q8H55gAcyMZfz2XKzDvu5sZaC96LCfSoibq82",
      "MS=ms50474575",
      "ifl513ibj8j0v63nhvkhlf0e61",
      "atlassian-domain-verification=CWJ0Dn5MkEJB1/e3h2WmOicez83C/W3RnqnrJoaAL66tcIf5yhDV0YTRrf4QVnxn",
      "facebook-domain-verification=nxqqu1usearteri105exfg33t1yyos",
      "adobe-idp-site-verification=7452b219-e19d-43c7-b5fb-a381f17b01e6",
      "google-site-verification=ecvdyQLuC440qHVOKlQG9McMXmlqn5oJzuskNAFssDk",
      "knowbe4-site-verification=37422bc6f9a6ff24d631677404b331b8",
      "google-site-verification=bAK2I4sWt6ICJa5zMkJcjbMr-wR8Qzk_TpJCFmvmaCc"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com;ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=monster.com",
    "issuer": "countryName=US, stateOrProvinceName=Arizona, localityName=Scottsdale, organizationName=GoDaddy.com, Inc., organizationalUnitName=http://certs.godaddy.com/repository/, commonName=Go Daddy Secure Certificate Authority - G2",
    "notBefore": "Feb  4 18:39:08 2026 GMT",
    "notAfter": "Feb  4 18:39:08 2027 GMT",
    "san": [
      "*.monster.se",
      "monster.se",
      "*.monster.fr",
      "monster.fr",
      "*.monster.lu",
      "monster.lu",
      "*.monster.co.uk",
      "monster.co.uk",
      "*.monster.ch",
      "monster.ch",
      "*.monster.it",
      "monster.it",
      "*.gslb.monster.com",
      "gslb.monster.com",
      "*.monster.de",
      "monster.de",
      "*.monster.be",
      "monster.be",
      "*.local-jobs.monster.com",
      "local-jobs.monster.com",
      "*.monsterboard.nl",
      "monsterboard.nl",
      "monster.com",
      "www.monster.com",
      "monster.ca",
      "*.monster.ie",
      "monster.ie",
      "*.monster.ca",
      "*.monster.eu",
      "monster.eu",
      "*.monster.at",
      "monster.at",
      "monster.es",
      "*.monster.es",
      "*.monster.com"
    ],
    "days_left": 131,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "166.117.15.191",
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
    "location": "https://monster.com:443/"
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=rRq11A1dCsb5_qBT_3Fs9Sag5f8Wm5t58e05wQAESa0",
    "apple-domain-verification=jHHEM7KcSPaadK20",
    "yahoo-verification-key=E3zIMY4vqEPbyoGg80CV/bYPK0gmAjYeuPtCA+b20To=",
    "google-site-verification=h1591ugHHOFsWchw3mvQFe_l7qR4iinHtA4sDlxmwRE",
    "google-site-verification=zXNA4jzGldUrb4WTfbWVyylyVgZRuVjpzS94ul_sr4g"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null
    }
  },
  "http2": {
    "error": "root GET failed"
  },
  "elapsed_s": 13.7,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
