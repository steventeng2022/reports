# Security Audit Report — monster.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://monster.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | monster.com |
| Test date | 2026-09-26 23:33 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 1, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 3 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 4 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 5 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 6 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 7 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 8 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 9 | info | TLS20 | Short certificate serial number (< 64 bits) | CWE-347 |

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
- **Detail:** Apex TXT records with verification/token content: apple-domain-verification=jHHEM7KcSPaadK20; google-site-verification=ecvdyQLuC440qHVOKlQG9McMXmlqn5oJzuskNAFssDk; facebook-domain-verification=nxqqu1usearteri105exfg33t1yyos
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 6. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.godaddy.com/ -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 7. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for monster.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 8. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The monster.com certificate lists an AIA OCSP responder (http://ocsp.godaddy.com/) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 9. [INFO] Short certificate serial number (< 64 bits) (`TLS20`)

- **CWE:** CWE-347
- **Detail:** Leaf certificate of monster.com carries a 62-bit serial (0x23258fef6c46be86); serials under 64 bits make collision attacks (2008 CERTEX) feasible and are no longer recommended by the CA/B Forum.
- **Recommendation:** Request certificates with 128-bit serial numbers.

## Evidence (raw response observations)

```json
{
  "domain": "monster.com",
  "dns": {
    "a": [
      "166.117.209.20",
      "166.117.15.191"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "ALT1.ASPMX.L.GOOGLE.com (pref 5)",
      "ALT3.ASPMX.L.GOOGLE.com (pref 10)",
      "ALT4.ASPMX.L.GOOGLE.com (pref 10)",
      "ASPMX.L.GOOGLE.com (pref 1)",
      "ALT2.ASPMX.L.GOOGLE.com (pref 5)"
    ],
    "ns": [
      "ns2.tmpw.net.",
      "ns1.tmpw.net."
    ],
    "caa": [],
    "spf": [
      "amazonses:gceEoeOqKvtfdmPp+y52S86QwEM6SHc4QH3ekZE3bpQ=",
      "_emotuf3vawbotgg5omeu1cvo2jhxdvu",
      "apple-domain-verification=jHHEM7KcSPaadK20",
      "oeIe2rwXtpnwFPKPFBl9AUpQpm1iDrxNx4NI18LFyR6cWwoIYsvRYfHhkxLg8PNGDw2IPkdD3q6w0cDi5wRxgA==",
      "google-site-verification=ecvdyQLuC440qHVOKlQG9McMXmlqn5oJzuskNAFssDk",
      "9uhsn2f7lot7574rnlm4ercqpb",
      "facebook-domain-verification=nxqqu1usearteri105exfg33t1yyos",
      "ciscocidomainverification=460719eb94004fbc3ffceb58ee7a94d0e45e14d1d224b3f193f0d122a6bdfbae",
      "dell-technologies-domain-verification=monster.com_14b47215-d44f-4358-908e-2b7892392b4c_1722463976",
      "onetrust-domain-verification=0ec2972887414a679d57a96ccc29b5b0",
      "v=spf1 mx ip4:220.226.205.66/32 ip4:208.71.192.0/21 ip4:193.164.143.0/24 ip4:64.127.116.65/26 ip4:64.127.121.0/27 ip4:98.174.21.153 ip4:69.25.33.0/24 include:spf.protection.outlook.com include:amazonses.com include:zgateway.zuora.com include:_spf.google.c",
      "om include:_spf.salesforce.com ip4:34.237.212.16/32 ip4:18.136.40.242/32 ip4:44.238.220.251/32  ~all",
      "_gkbtqbmmu4k082wtt6q501wxlf0r48a",
      "knowbe4-site-verification=37422bc6f9a6ff24d631677404b331b8",
      "datadome-domain-verify=B3KUK3qaB3COSjvTsFb9ZlUuVKr8F0ZJ",
      "google-site-verification=zXNA4jzGldUrb4WTfbWVyylyVgZRuVjpzS94ul_sr4g",
      "atlassian-domain-verification=CWJ0Dn5MkEJB1/e3h2WmOicez83C/W3RnqnrJoaAL66tcIf5yhDV0YTRrf4QVnxn",
      "adobe-idp-site-verification=7452b219-e19d-43c7-b5fb-a381f17b01e6",
      "GOytBs9lVe7A6ONbpEz1H+ouv1k8wnclMo3W48PX7mnZBaxXqJpJxTR5cdRPkUnunTbWui64V/PCEOOZDZsEXg==",
      "google-site-verification=bAK2I4sWt6ICJa5zMkJcjbMr-wR8Qzk_TpJCFmvmaCc",
      "webexdomainverification.=d6c0c09e-1efb-4b83-ac2c-c8b15118cc48",
      "ZOOM_verify_943D2iGtnuDRLVbiPRdQdz",
      "google-site-verification=h1591ugHHOFsWchw3mvQFe_l7qR4iinHtA4sDlxmwRE",
      "atlassian-domain-verification=bKSyyEicgY0Nu7x4asJ5ja9ueF/q8H55gAcyMZfz2XKzDvu5sZaC96LCfSoibq82",
      "cloudhealth=471ef53e-b947-4d03-adf9-ca29bb43a8c3",
      "yahoo-verification-key=E3zIMY4vqEPbyoGg80CV/bYPK0gmAjYeuPtCA+b20To=",
      "google-site-verification=rRq11A1dCsb5_qBT_3Fs9Sag5f8Wm5t58e05wQAESa0",
      "ifl513ibj8j0v63nhvkhlf0e61",
      "MS=ms50474575"
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
    "days_left": 130,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "166.117.209.20",
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
    "apple-domain-verification=jHHEM7KcSPaadK20",
    "google-site-verification=ecvdyQLuC440qHVOKlQG9McMXmlqn5oJzuskNAFssDk",
    "facebook-domain-verification=nxqqu1usearteri105exfg33t1yyos",
    "ciscocidomainverification=460719eb94004fbc3ffceb58ee7a94d0e45e14d1d224b3f193f0d1",
    "dell-technologies-domain-verification=monster.com_14b47215-d44f-4358-908e-2b7892"
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
      "aia_ocsp": "http://ocsp.godaddy.com/",
      "serial": 2532588623942303366,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.godaddy.com/gdig2s1-72078.crl"
      ],
      "subject_dn": "311430120603550403130b6d6f6e737465722e636f6d",
      "issuer_dn": "310b30090603550406130255533110300e060355040813074172697a6f6e61311330110603550407130a53636f74747364616c65311a3018060355040a1311476f44616464792e636f6d2c20496e632e312d302b060355040b1324687474703a2f2f63657274732e676f64616464792e636f6d2f7265706f7369746f72792f313330310603550403132a476f2044616464792053656375726520436572746966696361746520417574686f72697479202d204732",
      "not_before": "20260204183908",
      "not_after": "20270204183908"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "error": "root GET failed"
  },
  "x12": {
    "error": "SSLError(MaxRetryError(\"HTTPSConnectionPool(host='monster.com', port=443): Max r"
  },
  "x13": {
    "root_error": "SSLError(MaxRetryError(\"HTTPSConnectionPool(host='monster.com', port=443): Max r",
    "http_status": 301,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "serial_bits": 62,
    "root_error": "SSLError(MaxRetryError(\"HTTPSConnectionPool(host='monster.com', port=443): Max r",
    "crl": {
      "url": "http://crl.godaddy.com/gdig2s1-72078.crl",
      "status": 200
    }
  },
  "elapsed_s": 22.7,
  "rechecked": "2026-09-26 23:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- Findings are reported against the public program scope; submission through the program tracker is pending.
