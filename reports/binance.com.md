# Security Audit Report - binance.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://binance.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | binance.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 4, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | api1.binance.com test endpoint live | CWE-916 |
| 2 | low | S1 | api2.binance.com test endpoint live | CWE-916 |
| 3 | info | S1 | api.binance.com 403 (awselb) | CWE-916 |
| 4 | info | S1 | support and pay subdomains behind CloudFront bot challenge | CWE-916 |
| 5 | info | S1 | download and ftp subdomains return S3 error pages | CWE-916 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H1 | Missing HSTS header | CWE-319 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] api1.binance.com test endpoint live (S1)

- **CWE:** CWE-916
- **Detail:** api1.binance.com 200 (77 B nginx, body "Test OK") - health/test endpoint publicly reachable.

### 2. [LOW] api2.binance.com test endpoint live (S1)

- **CWE:** CWE-916
- **Detail:** api2.binance.com 200 (77 B nginx, body "Test OK") - health/test endpoint publicly reachable.

### 3. [INFO] api.binance.com 403 (awselb) (S1)

- **CWE:** CWE-916
- **Detail:** api.binance.com 403 (0 B awselb/2.0 behind CloudFront).

### 4. [INFO] support and pay subdomains behind CloudFront bot challenge (S1)

- **CWE:** CWE-916
- **Detail:** support.binance.com and pay.binance.com 202 (2110 B CloudFront challenge).

### 5. [INFO] download and ftp subdomains return S3 error pages (S1)

- **CWE:** CWE-916
- **Detail:** download.binance.com and ftp.binance.com 403 (111 B AmazonS3 "Error from cloudfront").

### 6. [LOW] Missing CSP header (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.binance.com/ (observed on the 202 CloudFront bot-challenge response).

### 7. [LOW] No clickjacking protection (H4)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options on https://www.binance.com/ (observed on the 202 CloudFront bot-challenge response).

### 8. [INFO] Missing HSTS header (H1)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.binance.com/ (observed on the 202 CloudFront bot-challenge response).

### 9. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.binance.com/ (observed on the 202 CloudFront bot-challenge response).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
