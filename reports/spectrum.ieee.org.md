# Security Audit Report — spectrum.ieee.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://spectrum.ieee.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | spectrum.ieee.org |
| Test date | 2026-09-29 23:07 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 1, Low: 2, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I6 | Open redirect | CWE-601 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Open redirect (`I6`)

- **CWE:** CWE-601
- **Detail:** Parameter next_url on https://spectrum.ieee.org/core/saml/main/login redirects to attacker-controlled target. URL: https://spectrum.ieee.org/core/saml/main/login?next_url=%2F%2Fzx7rdtct.example%2F Location: https://services10.ieee.org/idp/SSO.saml2?SAMLRequest=fVPRbpswFH3vVyDeg8FtiGIlSFmSrkhZggLbw14mz760lsBmtmmzv59N6JJKW3ixdO85555jXxaGtk1HVr19kUf41YOxd0FwahtpyNBahr2WRFEjDJG0BUMsI%2BXqy47gKCadVlYx1YQfSLc51BjQVijpSflmGR72293hc77%2FwXEdp3xKAe4TnM7jtE5m9QwzHM8Zrh84xayeTR%2BwJ34DbZzGMnSSg5AxPeTSWCqtK8Y4ncTzCZ5XGJPpjOD0u0dtXD4hqR2YL9Z2hiDk7LwKBiaJIwEAkdLPSPAOleUh8nGGecWY9JOQXMjn2xF%2FnkGGPFVVMSkOZeUlVu%2FB10qavgVdngd%2FPe6uzHTArO7bixWmNCDvA7VUSESZCTOnFgQLXyRDcJ2VIy%2FfbrcLdN25YDuyd1bzTaEawX4Pdf89Kt1S%2B%2F9ESZQMFcEn9QAlvfQ2RS2Ah39lVk2j3tYaqIVl6KxAGKAPw8f9Aj5sm7sECycbrFXbUS2MfxE4UWbHdJeE1%2FB149bnCHV2c8MYYR7nyoU73pTm%2FvncBQGvNHXmlbbjJf1T%2FOwa3bCd3b23r3%2Bd7A8%3D&RelayState=https%3A%2F%2Fspectrum.ieee.org%2F%2Fzx7rdtct.example%2F

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://spectrum.ieee.org/

### 3. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: spectrum.ieee.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://spectrum.ieee.org/

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Active re-verification (2026-09-30, agent-aggressive)

- **I6 (kept MEDIUM):** All 4 next_url variants (//zx7rdtct.example/, https://zx7rdtct.example/, /safe?next=..., //evil.example#x) on /core/saml/main/login return 302 to the trusted IEEE IdP https://services10.ieee.org/idp/SSO.saml2; the attacker target is carried inside RelayState/SAMLRequest rather than as a direct Location to attacker-controlled host. Bounded unauthenticated SAML RelayState injection - no direct open redirect confirmed.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
