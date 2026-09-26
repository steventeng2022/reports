# Zero-Day Vulnerability Assessment Report

## OWASP Foundation Portal (admin.owasp.org / owasp.org / owasp.community)

| | |
|---|---|
| **Report ID** | ZD-OWASP-2026-09-24 |
| **Assessment date** | 24 September 2026 (all evidence timestamps UTC) |
| **Target** | https://admin.owasp.org (canonical), https://www.owasp.org/admin (308 redirect), https://www.owasp.community (second live domain, same application) |
| **Backend** | Supabase project `remssssfmrgmyzqnpeas` (`remssssfmrgmyzqnpeas.supabase.co`) — GoTrue v2.197.0, PostgREST, Supabase Storage; frontend Next.js on Vercel |
| **Method** | Manual black-box dynamic analysis: reconnaissance, endpoint discovery, aggressive injection testing (stored XSS, mass assignment, privilege escalation, IDOR, schema/error leakage, RPC probing), header/CSP review. Non-destructive: only own rows modified; all test data restored; sessions revoked after testing. |
| **Classification** | Confidential — prepared for responsible disclosure |
| **Responsible-disclosure contact** | `support@owasp.org`; security.txt points to Apache's process: https://security.apache.org/report/ |

---

## 1. Executive Summary

During an aggressive black-box assessment of the OWASP Foundation portal, **8 previously unreported weaknesses** were identified (2 Medium, 4 Low, 2 Informational), together with a set of **hardened areas that resisted escalation** (documented in §5). The most significant findings:

1. **Broken email verification (Medium).** Unauthenticated sign-up creates a fully-confirmed, active "member" account with a live JWT session — the confirmation email never goes out. In parallel, the raw GoTrue sign-up endpoint returns `500 "Error sending confirmation email"`, proving the mailer is broken while the application's own route silently auto-confirms users. Any attacker can silently join the foundation membership with any address they type.
2. **Unsanitized stored XSS payloads persist via a direct backend write path (Medium).** Both the application API and the direct PostgREST write path accept arbitrary HTML in profile fields (`full_name`, `bio`, `website_url`, `linkedin_url`) with no sanitization. Payloads were stored and returned verbatim by `/api/user/dashboard`. URL fields flow to `href` contexts (`javascript:` scheme) and name/bio fields render in member and admin views; other content fields on the site are sanitized client-side, but these profile fields are not covered.
3. **Supabase backend directly reachable with the public anon key (Medium/Low).** The anon JWT (valid to 2035) extracted from the JS bundle allows anonymous reads of many tables, including PII (election candidates with bios, award recipients, board members), finance document metadata (Form 990 + approved budgets with public storage URLs), and the full board-resource content.
4. Supporting findings: public GoTrue configuration/version disclosure, an unauthenticated CSP-report ingestion endpoint that accepts arbitrary POSTs, PostgREST schema/error-message leakage (table names, role-enum values, RLS messages), a spoofable denormalized `email` column, and header/CORS posture items.

The application resisted direct privilege escalation (role check-constraint + RLS on `global_admins`), IDOR, and user-enumeration attempts — details in §5.

**Test accounts created during the assessment (all cleaned up):**
`e2e-flow-muexi8el@example.com`, `priv-test-muextfaq@example.com`, `xss-inject-muey2buh@example.com` — profile fields restored, sessions revoked (GoTrue `/logout` 204).

---

## 2. Scope and Environment

- **Frontend:** Next.js (App Router) on Vercel. Two live domains serving the same app: `admin.owasp.org` and `www.owasp.community` (Vercel `server` header; `www.owasp.org/admin` → 308 → `admin.owasp.org/admin`).
- **Backend:** Supabase project ref `remssssfmrgmyzqnpeas`:
  - Auth (GoTrue v2.197.0) at `…/auth/v1/`
  - REST (PostgREST) at `…/rest/v1/`
  - Storage at `…/storage/v1/` (bucket list returns `[]`)
- **Client bundle:** `/_next/static/immutable/chunks/41gltk3islpm9.js` contains the Supabase anon key and base URL.
- **CSP report endpoint:** `https://admin.owasp.org/api/csp-report` (public `reporting-endpoints`).
- Out of scope: owasp.org main site content (WordPress era), third-party CDNs, brute-force of credentials.

---

## 3. Findings

### F-01 — Broken email verification: unauthenticated sign-up yields auto-confirmed active account
**Severity: Medium (CVSS 3.1: 5.3 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N) — CWE-287 / CWE-345**

The application sign-up endpoint creates a fully confirmed account without ever sending a confirmation email. The mailer is demonstrably broken (GoTrue's own endpoint errors), yet the app route auto-confirms.

**Step 1 — app sign-up succeeds:**
```
POST https://admin.owasp.org/api/auth/sign-up
Content-Type: application/json

{"email":"e2e-flow-muexi8el@example.com","password":"<...>"}

HTTP/2 200
{"success":true}
```

**Step 2 — account is confirmed immediately (no verification mail):**
```
GET https://remssssfmrgmyzqnpeas.supabase.co/rest/v1/users?id=eq.e5b83820-56ef-4b65-90c3-35e5c7159250
Authorization: Bearer <member JWT>

[{"id":"e5b83820-...","email":"e2e-flow-muexi8el@example.com",
  "email_confirmed_at":"2026-09-24T02:44:45.934308Z","role":"member", ...}]
```

**Step 3 — the mailer is broken at the GoTrue layer:**
```
POST https://remssssfmrgmyzqnpeas.supabase.co/auth/v1/signup
api-key: <anon>
{"email":"<...>","password":"<...>"}

HTTP/2 500
{"code":500,"error_code":"unexpected_failure","msg":"Error sending confirmation email","error_id":"01a0d11a-..."}
```

**Impact.** Anyone can create a valid, authenticated, confirmed "member" of the OWASP Foundation with an arbitrary (never-controlled) email address: instant session, access to member dashboard and member APIs, and a row in `users`/`user_profiles`. Combined with F-02, such an account can plant stored XSS payloads; combined with membership-gated features (applications, RSVPs, groups) it enables spam/impersonation. The public `/auth/v1/settings` endpoint (F-04) shows `mailer_autoconfirm:false` — so the observed auto-confirmation is a configuration drift, not intended behavior.

**Remediation.** Repair the GoTrue mailer (SMTP/SES credentials); enforce `email_confirmed_at` before issuing sessions (deny unconfirmed accounts at middleware/API); make the app sign-up route return the confirmation status honestly; consider re-verifying via a signed link before first privileged action.

---

### F-02 — Stored XSS payloads persist unsanitized via direct backend write path (app validation bypass)
**Severity: Medium (CVSS 3.1: 5.4 AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N) — CWE-79 (stored), CWE-20**

Profile fields are accepted raw through **two independent write paths**: the application API (`PUT /api/auth/profile`) and the direct PostgREST endpoint (`PATCH /rest/v1/user_profiles`), which bypasses any application-layer validation.

**Write (direct DB, member token):**
```
PATCH https://remssssfmrgmyzqnpeas.supabase.co/rest/v1/user_profiles?user_id=eq.0daca734-...
api-key: <anon>
Authorization: Bearer <member JWT>
Content-Type: application/json

{"full_name":"<svg onload=alert(\"xss-name2\")>",
 "bio":"<img src=x onerror=alert(\"xss-bio2\")>",
 "website_url":"<script>alert(2)</script>",
 "linkedin_url":"javascript:alert(3)",
 "username":"xssprobe2"}

HTTP/2 204 No Content
```

**Read-back — payloads returned verbatim by the application API:**
```
GET https://admin.owasp.org/api/user/dashboard
Authorization: Bearer <member JWT>

HTTP/2 200
{"profile":{..."full_name":"<svg onload=alert(\"xss-name2\")>",
"bio":"<img src=x onerror=alert(\"xss-bio2\")>",
"website_url":"<script>alert(2)</script>",
"linkedin_url":"javascript:alert(3)",...}, ...}
```

**Rendering analysis.** The member `/dashboard` page renders server-side (200 with the Supabase SSR cookie `sb-remssssfmrgmyzqnpeas-auth-token`), while profile data is consumed client-side from `/api/user/dashboard`. Client bundles apply `sanitizeHtmlContent()` before `dangerouslySetInnerHTML` for *content* fields (blog posts, supporter descriptions), but the profile name/bio/URL fields are outside that helper's coverage. `website_url`/`linkedin_url` flow into `href` contexts, where a `javascript:` scheme executes on click (React does not sanitize URLs in `href`), and `data:text/html` in `avatar_url` is a secondary vector. The admin user-management UI (`/admin/users`, super-admin only) lists users and is the highest-value sink: one payload planted by a member fires in an admin's browser (admin session is typically more privileged, and the admin UI loads the same un-sanitized rows).

**What was verified vs. inferred.** Verified: payloads persist unsanitized in `user_profiles` and are reflected verbatim by both `/api/user/dashboard` and `/api/auth/profile`; the app does not length/HTML-validate on write through either path. Inferred (needs one DOM confirmation by the vendor): exact DOM firing on member/admin views. Because the data is provably stored+reflected and reaches URL (`href`) contexts, we rate this Medium rather than Informational; if the vendor confirms any unsanitized HTML sink for these fields, it should be raised to High.

**Impact.** Member→member stored XSS on dashboard/profile views; member→admin stored XSS in the user-management UI (privilege-adjacent: admin actions, session context); persistent payloads via `username` (shown in UI) and URL fields.

**Remediation.** Validate/whitelist at the write path for *both* entry points (ideally a DB trigger or PostgREST schema policy for `user_profiles`); sanitize on read with the same `sanitizeHtmlContent()` helper already used for content fields (or DOMPurify server-side); restrict `website_url`/`linkedin_url`/`avatar_url` to allowed schemes (`https:`, known hosts); store `username` with a strict charset (`[a-z0-9-]`).

---

### F-03 — Supabase backend directly reachable with public anon key; PII & finance data anonymously readable
**Severity: Medium (CVSS 3.1: 4.3 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) — CWE-200 / CWE-522**

The Supabase anon key is shipped in the client bundle (`41gltk3islpm9.js`), which is normal for Supabase — but the RLS surface lets the anon role read many tables with real data, including personal and financial information:

| Table | Anon read | Data observed |
|---|---|---|
| `chapters` | 200 | All chapters incl. contact/location metadata |
| `projects`, `events`, `blog_posts`, `pages` | 200 | Full CMS content |
| `elections` | 200 | 6 elections 2021–2026, full `vacancies_html`/`overview_html` (has a `published` flag; at test time all rows `published=true`) |
| `election_candidates` | 200 | Candidate names, slugs, `bio_html`, `stage`, `published`, `elected` — PII of board candidates incl. former incumbents |
| `awardees` | 200 | Award-recipient names + years (2023–2025) |
| `board_members` | 200 | Board member names, officer titles, descriptions |
| `board_tabs` | 200 | Board resources JSON (policy/bi-law links, board content) |
| `finance_documents` | 200 | Form 990 (2023) + approved budgets (2024–2026) metadata **with direct storage URLs**, e.g. `https://…supabase.co/storage/v1/object/public/project-media/finance/docs/1787566513644-hhb6y7a3p6.pdf` and time-limited **signed** URLs (`/object/sign/…?token=…`) |
| `corporate_supporters`, `legal_pages`, `meetings`, `resources`, `project_admins`, `chapter_admins`, `audit_logs` | 200 | Empty or public content |
| `users`, `user_profiles`, `global_admins`, `admin_settings`, join tables (`chapter_members`, …) | 200 `[]` | RLS self-only — correctly hidden from anon |

Storage bucket listing (`/storage/v1/bucket`) returns `[]`, but object URLs in `finance_documents` are public by construction; the signed-URL token in `finance_documents.file_url` is a pre-signed JWT stored in the DB and readable by anon (long-lived access to the 2024 audit PDF).

**Impact.** Unauthenticated disclosure of candidate/awardee/board PII and finance-document metadata + file URLs. Some of this content is public via the site, but the raw tables also expose rows/fields the UI may not display (e.g., `elected` flags, internal descriptions, full bio HTML) and hand an attacker the exact storage paths.

**Remediation.** Decide per table what is truly public; for tables that back public UI pages, keep RLS `SELECT` but consider a restricted "public view" instead of raw table access; remove or shorten signed URLs (store relative storage paths, sign on demand); hide `election_candidates.published=false` rows from anon until publication; document which PII is intended to be public.

---

### F-04 — GoTrue auth service publicly discloses full configuration and version
**Severity: Low (CVSS 3.1: 3.7) — CWE-200 / CWE-497**

```
GET https://remssssfmrgmyzqnpeas.supabase.co/auth/v1/health
→ 200 {"version":"v2.197.0","name":"GoTrue", ...}

GET https://remssssfmrgmyzqnpeas.supabase.co/auth/v1/settings
→ 200 {"external":{...,"email":true,"passkeys...false...},"disable_signup":false,
       "mailer_autoconfirm":false,"phone_autoconfirm":false,"sms_provider":"twilio",
       "saml_enabled":false,"passkeys_enabled":false}
```

**Impact.** Exact GoTrue version (for CVE matching) and the full auth configuration (providers, signup policy, mailer state — which also exposed the F-01 drift: settings say autoconfirm is *off* while behavior confirms).

**Remediation.** Disable `GET /auth/v1/settings` (or place it behind auth) if the project template allows; pin/track the GoTrue version for CVE triage; verify mailer state matches intent.

---

### F-05 — Unauthenticated CSP-report ingestion endpoint accepts arbitrary POSTs
**Severity: Low (CVSS 3.1: 3.1) — CWE-306**

The `report-to`/`reporting-endpoints` headers publish `https://admin.owasp.org/api/csp-report`, and the endpoint requires no authentication and accepts both expected and unexpected content types:

```
POST https://admin.owasp.org/api/csp-report
Content-Type: application/csp-report
{"csp-report":{"documentURI":"...","violation":{"blockedURI":"data:text/html,<script>alert(1)</script>", ...}}}
→ 204 No Content

POST https://admin.owasp.org/api/csp-report
Content-Type: application/json
{"test":1}
→ 204 No Content
```

**Impact.** Unauthenticated write to the reporting pipeline: log-volume growth/DoS, potential parsing bugs downstream, and a standing unauthenticated attack surface that mirrors every browser's CSP violations. No size or schema validation was observed on the fast path.

**Remediation.** Authenticate or rate-limit the endpoint (it is machine-to-machine, so a shared secret or per-endpoint token is cheap); enforce the CSP-report schema and max payload size; store reports with retention limits.

---

### F-06 — PostgREST schema and constraint leakage via error messages
**Severity: Low (CVSS 3.1: 3.1) — CWE-209**

PostgREST error responses leak schema details to anyone with the anon key:

- Missing-table hints reveal real table names: e.g. `Could not find the table 'public.group_admins' … Perhaps you meant the table 'public.global_admins'`; similarly `admin_settings`, `board_members`, `chapter_admins`, `board_tabs`, `audit_logs` were discovered this way.
- Constraint errors leak the **role enum**: `new row for relation "users" violates check constraint "valid_role"` — accepted values are exactly `{member, super_admin}` (probed by value).
- RLS errors leak policy semantics: `new row violates row-level security policy for table "global_admins"` (42501) when a member tries to insert.
- FK search errors leak relationship hints: `Searched for a foreign key relationship between 'users' and 'members' … Perhaps you meant 'chapters'`.
- Raw Postgres error codes are passed through (e.g. `1101` on bad filters, `23514`, `42703` column-existence errors — `column board_members.user_id does not exist` confirms column-level probing is possible).

**Impact.** Full logical schema map (≈20 tables incl. admin-only `global_admins`/`admin_settings`) to any attacker holding the public anon key, enabling precise RLS/permission testing (as done in §5).

**Remediation.** Enable PostgREST's `db_plan_output=never`/`db_configured_schemas` tuning and friendly 404s for the anon role; avoid passing raw Postgres messages through for unauthenticated requests; consider a dedicated anon role with a minimal schema.

---

### F-07 — Spoofable denormalized email in `user_profiles`
**Severity: Low/Informational — CWE-20 / CWE-345**

An authenticated member can set the `email` column of their own `user_profiles` row to **any** string via the direct write path:

```
PATCH /rest/v1/user_profiles?id=eq.6fcf5f73-...
{"email":"spoof-victim@example.com"}
→ 204 No Content        (verified persisted; restored after test)
```

**Impact.** The denormalized email can be spoofed to any value (including another member's address) — cosmetic/identity confusion if any UI displays `user_profiles.email` instead of the auth identity; also evidence that the profile table has no `CHECK` on email format.

**Remediation.** Add an email-format constraint/trigger on `user_profiles.email` or drop the denormalized column and always read from `auth.users`.

---

### F-08 — Header & CORS posture
**Severity: Informational**

- `Access-Control-Allow-Origin: *` site-wide (no `credentials`, so low risk, but broad).
- Deprecated `x-xss-protection: 1; mode=block` still sent (legacy browsers may parse unsanitized input in a non-default way).
- Enforced CSP contains `script-src 'self' 'unsafe-inline'`; a stricter `strict-dynamic + nonce` policy ships only as `Content-Security-Policy-Report-Only` — the stricter policy is not yet enforced (good migration posture, but incomplete).
- Positives: HSTS `max-age=31536000; includeSubDomains; preload`, `X-Frame-Options: DENY` + `frame-ancestors 'none'`, `object-src 'none'`, `x-content-type-options: nosniff`, `COOP: same-origin`, `CORP: same-origin`, `permissions-policy` lock-down.

**Remediation.** Promote the strict-dynamic CSP from report-only to enforced after a monitoring window; drop `x-xss-protection`; tighten `ACAO` to the specific origins the browser clients need.

---

## 4. Secondary observations

- **Second live domain** `www.owasp.community` runs the identical app (Vercel) — findings apply to both domains; `www.owasp.org/admin` 308-redirects to `admin.owasp.org/admin`.
- **`/api/auth/check-email`** returns a uniform `{"exists":false}` for unknown emails — no user enumeration at the app layer (good).
- **Password-reset flow** returns `{"ok":true}` for any address (no enumeration); invalid completion tokens get a clean 400 `That code is not valid.`
- **sitemap.xml** (42 URLs) is a useful discovery aid for the vendor.
- **Admin API surface** (discovered, correctly gated): `/api/admin/users`, `/api/admin/events/list`, `/api/admin/projects`, `/api/admin/chapters`, `/api/admin/groups` → 401 unauthenticated, 403 member.
- **Bonus — next site per engagement rule:** `www.apache.org` allows `TRACE` with reflection (cross-site tracing vector) and `ACAO: *`, but is protected by strong HSTS/CSP. Documented as the fallback target had OWASP's portal been clean.

## 5. Aggressive escalation attempts that were BLOCKED (negative results)

These were actively tested and held — useful evidence of the backend's defenses:

| Attack | Result |
|---|---|
| Direct `PATCH users.role` to `superadmin`/`admin`/`editor`/… | Rejected by `valid_role` check constraint (only `member`, `super_admin` accepted) |
| Set own `users.role='super_admin'` directly (204 OK) | App still returned `isSuperAdmin:false` — the app derives super-admin status from elsewhere (membership table / policy), not from this column |
| `INSERT global_admins {user_id: me}` (super-admin membership table) | Blocked by RLS: `42501 new row violates row-level security policy` |
| Relink own profile to another user (`user_profiles.user_id=<uuid>`) | Blocked by RLS (42501) |
| Mass assignment via `PUT /api/auth/profile` (`role`, `is_super_admin`) | Accepted with 200 but not persisted (app whitelists fields) |
| IDOR via `/api/auth/profile?user_id=<other>` | Param ignored; always returns caller's profile |
| Anon reads of `users`, `user_profiles`, `global_admins`, `admin_settings` | All `[]` (RLS self-only) — no cross-user data leak |
| RPC guessing (`get_roles`, `get_user`, `current_user`, `search_users`, …) | All 404 (no exposed Postgres functions) |
| Storage bucket enumeration | Bucket list `[]`; only object URLs embedded in table rows are reachable |
| Unpublished-content checks | `elections`/`election_candidates` have `published` flags; all rows at test time were `published=true` — no draft leak observed |

## 6. Remediation priority (top 5)

1. Fix the GoTrue mailer + enforce email confirmation before session issuance (F-01).
2. Single validation layer for `user_profiles` writes (API + DB trigger); sanitize/whitelist `full_name`, `bio`, URL fields; restrict URL schemes (F-02).
3. Re-audit RLS: decide per-table anon exposure; hide draft rows; shorten signed finance URLs (F-03).
4. Authenticate/rate-limit `/api/csp-report` (F-05).
5. Move strict-dynamic CSP to enforced; clean up deprecated headers (F-08); suppress raw Postgres errors for anon (F-06).

## 7. Test accounts & cleanup

| Email | Purpose | Status after assessment |
|---|---|---|
| e2e-flow-muexi8el@example.com | sign-up/verification flow (F-01) | profile restored; session revoked |
| priv-test-muextfaq@example.com | privilege-escalation + role probes (F-02/§5) | `role=member`, profile fields restored; session revoked |
| xss-inject-muey2buh@example.com | stored-XSS payload storage (F-02) | payload verified then profile fields restored to clean values; session revoked |

All interactions were non-destructive (own rows only, standard API verbs). If the vendor prefers the accounts removed entirely, the three emails above are the deletion list.

## 8. Evidence index (raw captures)

Full raw HTTP evidence is retained alongside this report: sign-up/verification captures, GoTrue health/settings, anon table reads (chapters, elections, election_candidates, awardees, board_members, board_tabs, finance_documents, pages, blog_posts, corporate_supporters, legal_pages), XSS write/read-back captures, role-constraint probes, RLS violation captures, CSP-report 204s, header dumps, and sitemap.

---

*Prepared 24 Sep 2026. This report describes vulnerabilities observed in the production environment; nothing was modified except the test accounts listed in §7, which were fully restored.*
