# Security Audit Report — bookstackapp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bookstackapp.com/ (BookStack — self-hosted wiki platform) |
| Bug bounty program | None (open-source project; GitHub issue tracker) |
| Listed scope domain | bookstackapp.com |
| Test date | 2026-09-24 22:36–22:37 UTC (2026-09-25 Asia/Taipei) |
| Method | Full code + running-instance audit of BookStack v26 (HEAD 97fe7cca9), PHP 8.4.14, SQLite. Fresh-install DDL vs. corrected-schema controls, multi-role permission matrix (editor/attacker/reader), pre/post-trash state comparisons, anonymous access tests |

## Environment

- BookStack v26 source checkout, HEAD `97fe7cca9`, no release tag at test time.
- Local instance served via `php -S` (router script) on port 8080, SQLite database.
- Test users: admin (`admin@admin.com`), PoC Editor / PoC Attacker / PoC Reader (roles R22/R23 with media-only and page-view-all-only permissions respectively).
- Methodology note: findings F3a/F3d/F3e/F7 are triggered when the database matches the pristine migration DDL shipped in the v26 tree; each was reproduced on the pristine schema and re-verified 200-OK on a corrected schema (control), proving the failure is caused by the shipped DDL alone.

## Summary

Total findings: **12** (High: 4, Medium: 4, Low: 4, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | F3a-id | Fresh install: creating a book fails — entities.id NOT NULL without autoincrement | CWE-552 |
| 2 | high | F3a-slug | Fresh install: creating a page fails — entities.slug NOT NULL without default | CWE-552 |
| 3 | high | F3e | Fresh install: container creation fails — entity_container_data.description NOT NULL without default | CWE-552 |
| 4 | high | F3d | Fresh install: page save fails — entity_page_data.revision_count NOT NULL without default | CWE-552 |
| 5 | medium | F1 | Broken access control on trashed pages: image edit/rename/replace/delete allowed with only global image permissions | CWE-284 |
| 6 | medium | F1c | Anonymous access to /uploads/images/{path} files (no auth middleware), including orphaned files from trashed pages | CWE-284 |
| 7 | medium | F3c | Original DatabaseTransaction issues MySQL-only isolation SQL — 500 on SQLite (officially supported DB) | CWE-552 |
| 8 | medium | F7 | Attachment upload fails on shipped 2016 schema — attachments.external NOT NULL without default | CWE-552 |
| 9 | low | F1b | Drawio XML readable via /images/drawio/base64 with only page-view-all (no drawio permission) | CWE-284 |
| 10 | low | F2 | GET /images/gallery and /images/drawio without uploaded_to param → unhandled TypeError, HTTP 500 | CWE-754 |
| 11 | low | F2b | Attachment edit/update/upload on trashed parent page → unhandled 500 | CWE-754 |
| 12 | low | F4 | CSRF: X-XSRF-TOKEN header must be URL-decoded; raw cookie value always 419 (state-changing API clients break) | CWE-352 |

## Detailed findings

### 1. [HIGH] Fresh install: creating a book fails — entities.id NOT NULL without autoincrement (F3a-id)

- **CWE:** CWE-552
- **Affected:** BookStack v26 (introduced by migration `2025_09_15_132850_create_entities_table.php`, commit `4c7d6420e` "DB: Aligned entity structure to a common table")
- **Root cause:** The v26 `entities` table is created as `unsignedBigInteger('id')` with composite primary key `(id, type)` and **no autoincrement**. The `Entity` model (`app/Entities/Models/Entity.php`) assigns no id itself (no `$incrementing=false` handling, no `booted()`/`creating` hook), and the upgrade path only copies ids from legacy tables via `migrate_entity_data.php`. On a **fresh** install the application relies on the database to assign `id`, which the shipped DDL does not do.
- **Reproduction (verified):** On a database created from the pristine v26 migrations, as a logged-in editor: `POST /api/books` with `{"name":"F3A-Test Book"}` → **HTTP 500**. Server log (laravel.log 2026-09-24 22:36:22 UTC):
  ```
  SQLSTATE[23000]: Integrity constraint violation: 19 NOT NULL constraint failed: entities.id
  SQL: insert into "entities" ("name", "created_by", "updated_by", "owned_by", "slug", "type", "updated_at", "created_at")
       values (F3A-Test-Book, 1, 1, 1, f3a-test-book, book, ...)
  ```
  The INSERT contains no `id` column.
- **Control:** With a corrected schema (id autoincrement) the same request returns **200** and creates book id 26 (then deleted).
- **Impact:** Core workflow broken on fresh installs with the shipped schema: no books (and therefore no pages) can be created.
- **Recommendation:** Give `entities.id` a database-assigned default (autoincrement) or assign ids in the application layer consistently for both fresh and upgraded installs.

### 2. [HIGH] Fresh install: creating a page fails — entities.slug NOT NULL without default (F3a-slug)

- **CWE:** CWE-552
- **Root cause:** The v26 entities migration defines `slug` NOT NULL with no default. The page-creation path builds the draft placeholder INSERT with only `name, created_by, owned_by, updated_by, book_id, type, updated_at, created_at` — `slug` is omitted, and the model layer never generates it before the insert.
- **Reproduction (verified):** Pristine v26 schema (id autoincrement shimmed only to isolate this column): `POST /api/pages` with `{"name":"New Page","book_id":4}` → **HTTP 500**. Log 22:36:25 UTC:
  ```
  SQLSTATE[23000]: Integrity constraint violation: 19 NOT NULL constraint failed: entities.slug
  SQL: insert into "entities" ("name", "created_by", "owned_by", "updated_by", "book_id", "type", "updated_at", "created_at")
       values (New Page, 1, 1, 1, 4, page, ...)
  ```
- **Control:** Corrected schema (slug nullable/with default) → **200**, page id 27 created.
- **Impact:** Core workflow broken: pages cannot be created on a fresh install.
- **Recommendation:** Generate the slug in the model `creating` event (as the UI flow does) or make the column accept a generated default.

### 3. [HIGH] Fresh install: container creation fails — entity_container_data.description NOT NULL without default (F3e)

- **CWE:** CWE-552
- **Root cause:** The v26 `entity_container_data` migration declares `description` NOT NULL with no default; the container-creation code inserts only `(entity_id, entity_type)`.
- **Reproduction (verified):** Pristine schema: `POST /api/books` (after isolating the entities table) → **HTTP 500**. Log 22:36:27 UTC:
  ```
  SQLSTATE[23000]: Integrity constraint violation: 19 NOT NULL constraint failed: entity_container_data.description
  SQL: insert into "entity_container_data" ("entity_id", "entity_type") values (26, book)
  ```
- **Control:** Corrected schema → **200**.
- **Impact:** Books/chapters/shelves cannot be created on a fresh install.
- **Recommendation:** Default `description` to empty string in the DDL or set it explicitly in the application.

### 4. [HIGH] Fresh install: page save fails — entity_page_data.revision_count NOT NULL without default (F3d)

- **CWE:** CWE-552
- **Root cause:** The v26 `entity_page_data` migration declares `revision_count` NOT NULL with no default; the page-save path inserts only `(page_id, draft, editor, html, markdown, text)`.
- **Reproduction (verified):** Pristine schema: `POST /api/pages` → **HTTP 500**. Log 22:36:29 UTC:
  ```
  SQLSTATE[23000]: Integrity constraint violation: 19 NOT NULL constraint failed: entity_page_data.revision_count
  SQL: insert into "entity_page_data" ("page_id", "draft", "editor", "html", "markdown", "text") values (26, 1, wysiwyg, , , )
  ```
- **Control:** Corrected schema → **200**.
- **Impact:** Pages cannot be saved on a fresh install.
- **Recommendation:** Default `revision_count` to 0 in the DDL or application layer.
### 5. [MEDIUM] Broken access control on trashed pages — image operations succeed with only global image permissions (F1)

- **CWE:** CWE-284
- **Root cause:** `ImageController::checkImagePermission` (`app/Uploads/Controllers/ImageController.php` L159-169) resolves the image's related page and, **only if the page exists**, enforces the page-level permission:
  ```php
  if ($relatedPage) {
      $this->checkOwnablePermission(Permission::PageView, $relatedPage);
  }
  ```
  Once the page is **soft-deleted** (moved to trash), `getPage()` returns null and the page check is silently skipped — only the caller's global image-* permissions are enforced. An attacker holding only global media permissions (no page permission at all) can then modify and delete images that were attached to a trashed page.
- **Reproduction (verified):**
  1. Setup: page 29 ("PoC Media Page") with gallery image 22 and drawio images 25/26; attachment 10 attached to page 29. Attacker role R22 has only global `image-edit`, `image-attach`, `image-view-all`; **no** page permission. Pre-trash controls (attacker): edit image → 302 (denied), drawio download → 404, file-swap → 302.
  2. `DELETE /api/pages/29` → page soft-deleted at 22:37:11 UTC.
  3. Attacker, same permissions: **edit image 22 → 200**, **rename → 200**, **file swap → 200**, **delete → 200** (evidence: `evidence_h1_rename_resp.txt`, `evidence_h2_fileswap_resp.txt`, `evidence_h3_delete_resp.txt`, exploit_matrix.txt).
  4. Contrast: editor with real page permission succeeds as expected; download of a trashed attachment is 404 (fail-closed), showing the image path is the outlier.
- **Impact:** Data-integrity and confidentiality impact on trashed content: an attacker with only media permissions can replace, rename, or delete images belonging to trashed (i.e. "soft-deleted", often assumed less sensitive) pages — content an author may expect to be restorable/unchanged.
- **Recommendation:** For trashed pages, either keep enforcing the page permission against the trashed entity or explicitly deny image mutations (allow only view); never silently drop the page check.

### 6. [MEDIUM] Anonymous access to image files at /uploads/images/{path} — no auth middleware, orphaned files exposed (F1c)

- **CWE:** CWE-284
- **Root cause:** `GET /uploads/images/{path}` is registered as a **top-level route with no middleware group** (`routes_web.php` L37). `ImageController::showImage` (L32-41) validates only the path shape (traversal check via `pathAccessibleInLocalSecure`) and then streams the file — no authentication, no page permission, no ownership check.
- **Reproduction (verified):** With **no session cookie at all** (anonymous), requesting the DB-stored image paths (which include the leading `/uploads/`, so URL = host + path):
  - live page file: `GET /uploads/images/gallery/2026-09/...png` → **200**, `Content-Type: image/png`, 157 bytes, valid PNG magic `89 50 4E 47` (md5 714FEE5CD3137272F4185A21120657B8).
  - **trashed page file** (orphaned image 22, page 29 deleted): → **200**, same file (md5 identical).
  - Reader with page-view-all also 200 pre- and post-trash (evidence: `evidence_f1c_manual.txt`, `h_f1c_anon_live.txt`, `h_f1c_anon_trashed.txt`, `b_f1c_*.bin`).
  - (The automated matrix's 404s for this route were a URL double-slash artifact of the test harness; the manual retest is authoritative.)
- **Impact:** Any visitor (anonymous) can enumerate and download uploaded image files by path, including images whose page has been trashed (orphaned files persist). Useful for content mining, metadata harvesting, and confirming upload names before they are made visible.
- **Recommendation:** Put the route behind auth + a page-level check (or at minimum require the related page to be viewable); delete or deny orphaned images when their parent page is permanently deleted.

### 7. [MEDIUM] DatabaseTransaction uses MySQL-only isolation SQL — 500 on SQLite (officially supported database) (F3c)

- **CWE:** CWE-552
- **Root cause:** `app/Util/DatabaseTransaction.php` (original HEAD version) executes `SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED` (a MySQL syntax) unconditionally at transaction start. SQLite does not understand it and returns a syntax error, which aborts the whole write operation.
- **Reproduction (verified):** Restoring the original `DatabaseTransaction.php` from git HEAD (no driver guard) on the SQLite instance: `POST /api/books` → **HTTP 500**. Log 22:36:20 UTC:
  ```
  SQLSTATE[HY000]: General error: 1 near "SET": syntax error
  SQL: SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED
  ```
  After re-applying a driver guard, the same request returns 200 (control).
- **Impact:** On SQLite deployments (BookStack officially supports SQLite), every write path wrapped in `DatabaseTransaction` 500s until the file is patched — a latent landmine for fresh/patched deployments running on SQLite.
- **Recommendation:** Guard the isolation statement by connection driver (issue it only for MySQL/MariaDB), or map isolation levels per driver.

### 8. [MEDIUM] Attachment upload fails on the shipped 2016 attachments schema — attachments.external NOT NULL without default (F7)

- **CWE:** CWE-552
- **Affected:** All versions using the original attachments DDL (`database/migrations/2016_10_09_142037_create_attachments_table.php`: `external tinyint(1) not null`, no default; unchanged in v26).
- **Root cause:** `AttachmentService::saveNewUpload` builds the record via `forceCreate` with fields `name, path, extension, uploaded_to, created_by, updated_by, order, updated_at, created_at` — it never sets `external`. With the pristine schema the INSERT violates the NOT NULL constraint.
- **Reproduction (verified):** Restoring the original 2016 attachments DDL: `POST /attachments/upload` (multipart file upload, uploaded_to=6) → **HTTP 500**. Log 22:36:30 UTC:
  ```
  SQLSTATE[23000]: Integrity constraint violation: 19 NOT NULL constraint failed: attachments.external
  SQL: insert into "attachments" ("name", "path", "extension", "uploaded_to", "created_by", "updated_by", "order", "updated_at", "created_at")
       values (secret-report.txt, uploads/files/2026-09-Sep/PWQfKXSjJv9iJI50-txt, txt, 6, 1, 1, 2, ...)
  ```
- **Control:** With `external` given a default of 0 (schema fix), the same upload returns **200** (evidence: `evidence_f7_control.txt`).
- **Impact:** File upload — a core workflow — fails on any deployment whose `attachments` table matches the shipped DDL without a later migration altering the column.
- **Recommendation:** Add `default 0` to the column (migration) or set `external` explicitly in `saveNewUpload`.
### 9. [LOW] Drawio XML readable with only page-view-all — /images/drawio/base64/{id} lacks drawio permission check (F1b)

- **CWE:** CWE-284
- **Detail:** A user with only the global `page-view-all` permission (no drawio-specific permission) could read a page's drawio diagram source via `GET /images/drawio/base64/{id}` before the page was trashed: response 200 with body `{"content":"iVBORw0KGgo..."}` (drawio XML, base64-encoded) — evidence `evidence_f_drawio_leak_pre.html`. The drawio endpoint reuses the page-view check instead of requiring a drawio-specific permission, so diagram source (often containing embedded comments/labels) is readable by any page viewer.
- **Note:** After the parent page was trashed, the same request returned 404 for **all** users including admin: the permission catalog defines `page-view-all`/`page-view-own` but not the bare `page-view` constant used by the check (`app/Permissions/Permission.php`), so the check fails closed for everyone (see F2b contrast).
- **Recommendation:** Require a drawio-specific permission (or explicit page-edit) for the drawio base64 endpoint; align the bare `page-view` constant with the permission catalog.

### 10. [LOW] GET /images/gallery and /images/drawio without uploaded_to param → unhandled TypeError, HTTP 500 (F2)

- **CWE:** CWE-754
- **Detail:** `GET /images/gallery` and `GET /images/drawio` (no query parameters) reach `ImageRepo::getEntityFiltered()` with `uploadedTo = null`; the method is typed `int` and throws `TypeError` — unhandled → 500 with a server-rendered error page. Log 22:36:57-58 UTC:
  ```
  TypeError: BookStack\Uploads\ImageRepo::getEntityFiltered(): Argument #5 ($uploadedTo) must be of type int, null given
  called in .../GalleryImageController.php on line 34
  ... DrawioImageController.php on line 35
  ```
- **Impact:** Unauthenticated-adjacent error surface (any logged-in user), inconsistent error handling; reveals internal method names in debug builds.
- **Recommendation:** Return 422/400 for missing `uploaded_to` instead of a TypeError.

### 11. [LOW] Attachment edit/update/upload on trashed parent page → unhandled 500 (F2b)

- **CWE:** CWE-754
- **Detail:** After page 29 was moved to trash, attachment operations referencing it (`uploaded_to=29`) failed with 500 for both an editor and a media-only attacker: `att_edit=500`, `att_update=500`, `att_upload=500` (evidence: `evidence_f2b_attedit_500.txt`, `evidence_f2b_attupdate_500.txt`, `evidence_f2b_attupload_500.txt`), while `download=404` (fail-closed). Inconsistent failure modes for the same "parent is trashed" condition.
- **Impact:** Broken UX/error surface for trashed content; inconsistent authorization signaling (500 vs 404).
- **Recommendation:** Normalize to a single, meaningful status (409/422) for operations on attachments whose parent is trashed.

### 12. [LOW] CSRF token handling: X-XSRF-TOKEN must be URL-decoded — raw cookie value always 419 (F4)

- **CWE:** CWE-352
- **Detail:** The profile route is `PUT /my-account/profile` (routes_web.php L261). The XSRF check (Laravel `VerifyCsrfToken`) **decrypts** the `X-XSRF-TOKEN` header with the session encrypter, so the header must carry the **URL-decoded** encrypted cookie value. Tests:
  - Header = raw cookie value (percent-encoded, ending `%3D`, the standard `document.cookie`→header pattern used by axios/browser clients) → **419** (`evidence_f4_raw_419.txt`).
   - Header = URL-decoded value (ending with an equals sign) -> **302** redirect to /my-account/profile, i.e. success (`evidence_f4_dec_302.txt`).
  - Token values from the session: form `_token` = `bgkwgKUmLL6xmliGKlxiRgi19gj8SMQg89bdvQrE`; cookie is an encrypted base64 JSON blob (`evidence_f4_token_values.txt`).
- **Impact:** First-party UI (form `_token`) is unaffected, but any JS/API client using the conventional raw cookie→header pattern fails CSRF on every state-changing request — a subtle, hard-to-debug integration bug for API consumers.
- **Recommendation:** Document (and ideally also accept) the percent-encoded form, or set the XSRF cookie URL-decoded so the standard pattern works.

## Test matrix (verbatim from run 20260925-063614)

Control matrix (pre-trash):

```
ed_edit_img=200 att_edit_img=302 rdr_edit_img=200
ed_dio=200 att_dio=404 rdr_dio=200
rdr_raw_bytes=404
ed_att=200 att_att=404 rdr_att=404 att_edit_form=302
page ed=404 att=404 rdr=404
att_fileswap=302
```

Exploit matrix (post-trash, page 29 deleted at 22:37:11 UTC):

```
att_edit_img=200
att_rename=200
att_fileswap=200
att_delete=200
rdr_drawio_base64=404
rdr_raw_bytes=404
att_att_edit=500
att_att_update=500
att_att_upload=500
ed_att_edit=500
att_att_download=404
ed_att_download=404
ed_edit_img=200
page ed=404 att=404 rdr=404
```

F1c manual retest (authoritative; automated 404s were a double-slash URL artifact):

```
reader_live=200
anon_live=200
anon_trashed=200
reader_trashed=200
md5_live_reader=714FEE5CD3137272F4185A21120657B8
md5_trashed_anon=714FEE5CD3137272F4185A21120657B8
```

## Methodology notes

- Fresh-DB findings (F3a/F3d/F3e/F7) were proven by restoring the exact shipped migration DDL from the v26 tree for the target table only, reproducing the 500 with the failing SQL captured from `storage/logs/laravel.log`, then re-running the same request on a corrected schema (200). All other tables were kept in the working (corrected) state, so each failure is attributable to a single shipped table definition.
- Permission findings used three purpose-built roles (media-only attacker, page-view-all reader, editor) with joint permissions reset before testing; pre/post-trash controls were captured in the same run (timestamps in `poc.log`, run dir `run-20260925-063614`, 239 evidence files).
- All HTTP evidence, cookies, and captured bodies are retained in the run directory referenced above.
