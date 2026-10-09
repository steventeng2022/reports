# High-Value Target Subdomain RCE-Surface Recon (Wave A)

**Prepared:** 2026-10-10 (UTC)
**Scope:** CT-cert subdomain discovery + live-probe of RCE-relevant panel/management
endpoints across 20 high-value parent domains (bank / crypto / SaaS / AI).
**Method:** Cert Spotter CT-log discovery (crt.sh fallback) → app-label keep filter →
DNS pre-filter → liveness → server-header CDN filter → endpoint probe
(Jenkins, Gitea, GitLab, Grafana, n8n, Solr, SonarQube, Kibana, Jolokia, Spring
Actuator, ColdFusion, WebLogic WLS-WSAT, phpMyAdmin). 155 subdomains probed,
22 raw hits, **4 confirmed real** (WAF path-echo false positives removed).

> This is a **recon / exposed-asset** report — internet-facing RCE *attack surface*
> discovered on top-tier targets. It is not a CVE write-up. The confirmed entries
> are the ones an attacker would actually reach; each was manually re-verified.

---

## 1. Confirmed real findings

### 1.1 `ccasalerts-gateway.wellsfargo.com` — exposed **WebLogic WLS-WSAT**  (parent: wellsfargo.com)

The strongest finding of the sweep. All four WLS-WSAT port types answer with a
genuine SOAP envelope over `https` (200, `content-type: text/xml`):

```
GET /wls-wsat/CoordinatorPortType?wsdl
GET /wls-wsat/RegistrationPortType?wsdl
GET /wls-wsat/Portal?wsdl
```

each returns a real `env:Envelope` → `env:Fault` ("Internal Error") body — the
canonical signature of an **Oracle WebLogic WLS-WSAT (Web Services Activation &
Transaction)** service. This is the exact attack surface behind
**CVE-2019-2725** (WLS-WSAT XXE → RCE) and a recurring WebLogic RCE/deserialization
family; a live, unauthenticated WLS-WSAT endpoint is therefore a directly
exploitable RCE candidate if the underlying WebLogic is in an affected version.

**Behaviour observed (read-only probes, no side effects):**
- `GET ?wsdl` on all port types → 200 SOAP fault envelope (service is up).
- Service answers identically over **`http://` and `https://`** (both 200,
  `text/xml`), and the context root `/console/` also routes into the same
  WLS-WSAT envelope — a broad, permissive mapping.
- `POST` SOAP body to `RegistrationPortType` → 200 but an **edge WAF**
  (Akamai-style "Request Rejected" / support-ID page) intercepts the request
  before it reaches the SOAP stack. So the WLS-WSAT service is live and reachable,
  but a modern edge WAF sits in front of the *write* path.

**Why it matters:** unauthenticated, network-reachable WebLogic WLS-WSAT on a
first-tier bank domain. Even with an edge WAF on POST, the exposed service is
worth a targeted CVE-2019-2725 / WLS-WSAT RCE test (version fingerprinting,
alternate encodings, and the 403/edge bypasses the WAF applies to specific
paths). **Highest-priority follow-up target of this sweep.**

---

### 1.2 `gwmportal.chase.com` and `gwmuiportal.chase.com` — Spring Boot **Actuator `/health`** exposed (parent: chase.com)

Both subdomains answer `https://…/actuator/health` (and `http://…/actuator/health`)
with `200 {"groups":["liveness","readiness"],"status":"UP"}` — a live Spring Boot
application exposing its management/actuator health endpoint to the internet.

Full actuator index (`/actuator`) also returns 200 and enumerates `self` +
`keepalive` + `health` + `health/{*path}`. The higher-value actuator endpoints
(`env`, `mappings`, `beans`, `threaddump`, `heapdump`, `configprops`, `loggers`,
`info`) were individually probed: they return **500** (i.e. present in the
registry but erroring/protected) rather than 404, and `/heapdump` returns 403 —
a mix that suggests the actuator is more exposed than a bare `health` would imply
and worth a deeper, authenticated-context probe.

**Why it matters:** an internet-exposed Spring Boot management surface on a Chase
subdomain. `env`/`beans`/`heapdump` exposure is the usual path to credential and
secret leakage and (on older Spring) RCE. Lower severity than the WebLogic find
but a clean, reproducible signal.

---

### 1.3 `buildingsassessment.business.hsbc.com` — Spring Boot **Actuator `/health`** exposed (parent: hsbc.com)

`https://…/actuator/health` and `http://…/actuator/health` → `200
{"groups":["liveness","readiness"],"status":"UP"}`. Same exposed-Spring-Boot-actuator
profile as the Chase hosts, on an HSBC "business" asset. Same follow-up logic
(enumerate `env`/`beans`/`heapdump`, check for an older exposed actuator build).

---

### 1.4 `uat.csmsuppliers.citi.com` — ServiceNow application behind a catch-all 200 (parent: citi.com)

`server: snow_adc`. Every probed path returns `200` with the **ServiceNow** app
title (a catch-all front that serves the ServiceNow instance). Not a classic
Jenkins/Solr/SonarQube panel — the "marker" strings matched only because the
catch-all returns the app for any path. Still a real, reachable ServiceNow UAT
instance on a Citi subdomain (ServiceNow has its own well-documented RCE and
auth-bypass history). **Medium confidence** — worth a targeted ServiceNow
enumeration pass.

---

## 2. Removed false positives (method note)

The other 18 raw hits were **not** real panels. Two distinct false-positive
mechanisms:

- **Edge-WAF path echo (403 "Access Denied" / 401).** Hosts on an Akamai-style
  edge (e.g. `api.financing.paypal.com`, `mfasa-qa2.chase.com`,
  `beta.chase.com`, `cpo-admin-reporting*.bankofamerica.com`,
  `*.aemapi.citi.com`, `dev*.services.citi.com`, `partnerportal.atlassian.com`)
  return a WAF "Access Denied" page whose **body echoes the requested path**.
  So `/jenkins/login`, `/solr/…`, `/phpmyadmin/`, `/CFIDE/administrator/` all
  "matched" their own marker simply because the URL string appears in the error
  page. **Removed:** all hits where the only signal is a 403/401 whose body
  contains the requested path.
- **Catch-all 200 with a generic product title** (the Citi ServiceNow case above —
  kept as a real but lower-confidence finding rather than dropped).

**Lesson for future sweeps:** a panel hit is only real if it is a `200` with a
matching *application* body (JSON key or app title), **or** a 401/403 that is
*not* a path-echoing WAF page. 403 "Access Denied" / 401 "Unauthorized" with the
requested path repeated in the body is a WAF, not the app.

---

## 3. Follow-up priority list

| # | Target | Surface | Priority | Next step |
|---|--------|---------|----------|-----------|
| 1 | `ccasalerts-gateway.wellsfargo.com` | WebLogic WLS-WSAT | **High** | Version fingerprint; CVE-2019-2725 XXE + WLS-WSAT RCE test against the edge WAF |
| 2 | `gwmportal.chase.com` | Spring Actuator | Med | Enumerate `env`/`beans`/`heapdump`; secret/cred leak |
| 3 | `gwmuiportal.chase.com` | Spring Actuator | Med | Same as above |
| 4 | `buildingsassessment.business.hsbc.com` | Spring Actuator | Med | Same as above |
| 5 | `uat.csmsuppliers.citi.com` | ServiceNow | Low-Med | ServiceNow enumeration / known RCE+auth-bypass checks |

---

## 4. Reproduce

Scanner: `scan/subscan3.py` (CT discovery via Cert Spotter, cached per parent in
`results/ct_cache/`). Full raw output: `results/subscan.json` + `results/subscan.md`.
WLS-WSAT manual probe: `scan/probe_wlswsat.py`.

*All confirmed entries were re-verified by direct request; the WAF-echo
false-positive class was identified by observing that the same 3–4 "markers"
reappear identically across unrelated hosts — a WAF signature, not a panel.*
