# Security Audit Report — myspace.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://myspace.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | myspace.com |
| Test date | 2026-09-25 17:54 UTC |
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
  "domain": "myspace.com",
  "dns": {
    "a": [
      "34.111.176.156"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-00ac0e01.gslb.pphosted.com (pref 10)",
      "mxb-00ac0e01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-cloud-a4.googledomains.com.",
      "ns-cloud-a1.googledomains.com.",
      "ns-cloud-a2.googledomains.com.",
      "ns-cloud-a3.googledomains.com."
    ],
    "spf": [
      "qpdYoeakhlmAxsnmxgAVFmJgUSibqb/y+Eu6GGn8pdmLf+mFGIB3jhRAxIC5KObsPMES9MW2c+oOrpOo/lCQVw==",
      "v=spf1 mx ip4:159.183.178.108 ip4:168.245.30.211 ip4:63.208.226.34 ip4:204.16.32.0/22 ip4:67.134.143.0/24 ip4:216.205.243.0/24 ip4:34.85.156.5/32 ip4:35.245.108.108/32 ip4:34.86.129.193/32 ip4:34.86.134.94/32 ",
      "ip4:34.85.222.234/32 ip4:34.86.176.234/32 ip4:34.86.125.212/32 ip4:34.85.224.60/32 ip4:34.86.160.49/32 ip4:35.245.64.166/32 ip4:35.188.226.11/32 ",
      "ip4:34.86.208.228/32 ip4:34.85.216.144/32 ip4:35.221.22.153/32 ip4:34.86.137.108/32 ip4:34.86.51.35/32 ip4:34.150.221.40/32 ip4:34.85.216.70/32 ip4:34.86.37.191/32 ip4:34.85.214.215/32 ",
      "ip4:35.236.234.82/32 ip4:34.86.161.241/32 ip4:216.32.181.16 ip4:216.178.32.0/20 ip4:168.235.224.0/24 include:_netblocks.mimecast.com -all",
      "google-site-verification=q0iWqpcfOBclAJaCeWh83v62QQ4uCgbWObQ08p37qgU",
      "cr40m536tje9on1slld9bi81bg",
      "MS=ms89904786",
      "cj65vjpq0s1v9u7vfo020c6rel",
      "google-site-verification=eu-3gW1JePvsGRRCaEvH17YUOTFJNofm4lnz2Pk0LTc",
      "oZ19a+EOIwWVDPJ7POj14UAGBfzk9xcJMmsTUAMUy7H82sDuVCxvw9rZqdg3znFrdTH04+49zd1djhEAt0ooiA==",
      "al4upe6q5cl13sg4srvfivflvg"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:postmaster@myspace.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=myspace.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR3",
    "notBefore": "Aug 17 20:48:06 2026 GMT",
    "notAfter": "Nov 15 21:44:01 2026 GMT",
    "san": [
      "myspace.com",
      "*.myspace.com"
    ],
    "days_left": 51,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.111.176.156",
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
    "location": "https://myspace.com:443/"
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 11.7,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
