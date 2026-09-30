# Security Audit Report - aol.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://aol.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | aol.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 12, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I4 | p param reflects in login href (attr context) | CWE-79 |
| 2 | low | I4 | s_qt param reflects in login href (attr context) | CWE-79 |
| 3 | low | I4 | rp param reflects in login href (attr context) | CWE-79 |
| 4 | low | I4 | s_chn param reflects in login href (attr context) | CWE-79 |
| 5 | low | I4 | s_it param reflects in login href (attr context) | CWE-79 |
| 6 | low | I4 | hspart param reflects in login href (attr context) | CWE-79 |
| 7 | low | I4 | hsimp param reflects in login href (attr context) | CWE-79 |
| 8 | low | I4 | v param reflects in login href (attr context) | CWE-79 |
| 9 | low | I4 | ncid param reflects in login href (attr context) | CWE-79 |
| 10 | low | I4 | return_to param reflects in login href (attr context) | CWE-79 |
| 11 | info | I22 | /callback?url propagates through the OAuth chain | CWE-538 |
| 12 | info | I22 | 20 redirect-style paths 308-redirect with params retained | CWE-538 |
| 13 | low | H2 | Missing CSP header | CWE-1021 |
| 14 | low | C1 | plid cookie set without Secure flag | CWE-614 |

## Detailed findings

### 1. [LOW] p param reflects in login href (attr context) (I4)

- **CWE:** CWE-79
- **Detail:** ?p=token reflects URL-encoded inside the homepage "Sign in" link href="https://auth.www.aol.com/login?return_to=https://www.aol.com/?p=..."; encoded-quote probe stays double-encoded (%2522) - no raw quote breakout.

### 2. [LOW] s_qt param reflects in login href (attr context) (I4)

- **CWE:** CWE-79
- **Detail:** ?s_qt=token reflects URL-encoded in the same login return_to attribute; encoded-quote probe re-encoded - no raw quote breakout.

### 3. [LOW] rp param reflects in login href (attr context) (I4)

- **CWE:** CWE-79
- **Detail:** ?rp=token reflects URL-encoded in the same login return_to attribute; encoded-quote probe re-encoded - no raw quote breakout.

### 4. [LOW] s_chn param reflects in login href (attr context) (I4)

- **CWE:** CWE-79
- **Detail:** ?s_chn=token reflects URL-encoded in the same login return_to attribute; encoded-quote probe re-encoded - no raw quote breakout.

### 5. [LOW] s_it param reflects in login href (attr context) (I4)

- **CWE:** CWE-79
- **Detail:** ?s_it=token reflects URL-encoded in the same login return_to attribute; encoded-quote probe re-encoded - no raw quote breakout.

### 6. [LOW] hspart param reflects in login href (attr context) (I4)

- **CWE:** CWE-79
- **Detail:** ?hspart=token reflects URL-encoded in the same login return_to attribute; encoded-quote probe re-encoded - no raw quote breakout.

### 7. [LOW] hsimp param reflects in login href (attr context) (I4)

- **CWE:** CWE-79
- **Detail:** ?hsimp=token reflects URL-encoded in the same login return_to attribute; encoded-quote probe re-encoded - no raw quote breakout.

### 8. [LOW] v param reflects in login href (attr context) (I4)

- **CWE:** CWE-79
- **Detail:** ?v=token reflects URL-encoded in the same login return_to attribute; encoded-quote probe re-encoded - no raw quote breakout.

### 9. [LOW] ncid param reflects in login href (attr context) (I4)

- **CWE:** CWE-79
- **Detail:** ?ncid=token reflects URL-encoded in the same login return_to attribute; encoded-quote probe re-encoded - no raw quote breakout.

### 10. [LOW] return_to param reflects in login href (attr context) (I4)

- **CWE:** CWE-79
- **Detail:** ?return_to=token reflects URL-encoded in the same login return_to attribute; encoded-quote probe re-encoded - no raw quote breakout.

### 11. [INFO] /callback?url propagates through the OAuth chain (I22)

- **CWE:** CWE-538
- **Detail:** /callback?url=canary 302 to auth.www.aol.com/login?url=... then 307 to api.login.aol.com/oauth2/request_auth (client_id lcVBgtoeIWdhMwbD, scope openid+openid2+profile+email+mail-aol-meta-r); token propagates through the chain and is not consumed as an open redirect.

### 12. [INFO] 20 redirect-style paths 308-redirect with params retained (I22)

- **CWE:** CWE-538
- **Detail:** /redirect, /r, /go, /out, /link, /continue, /next, /return, /redir, /jump, /url, /target, /follow (+u variants) 308 to trailing-slash variants with the param retained; second hop consumes the token - no open redirect.

### 13. [LOW] Missing CSP header (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.aol.com/ (X-Frame-Options SAMEORIGIN, HSTS and Referrer-Policy present).

### 14. [LOW] plid cookie set without Secure flag (C1)

- **CWE:** CWE-614
- **Detail:** plid (31536000 s / 1-year expiry, domain .aol.com, SameSite=Lax) set without the Secure flag.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
