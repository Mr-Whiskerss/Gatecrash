<div align="center">

```
             _                          _
  __ _  __ _| |_ ___  ___ _ __ __ _ ___| |__
 / _` |/ _` | __/ _ \/ __| '__/ _` / __| '_ \
| (_| | (_| | ||  __/ (__| | | (_| \__ \ | | |
 \__, |\__,_|\__\___|\___|_|  \__,_|___/_| |_|
 |___/
```

**Walk in behind a legitimate user and see what opens.**

</div>

---

An API security scanner for the first hour of a pentest engagement. Point it at a Postman
collection or OpenAPI spec plus a target host, give it two sets of credentials, and it hands
back findings with the raw request/response pairs that prove them.

Most API bugs are not injection — they are one user reaching another user's object, or a
standard account calling an admin function. Those are only findable by making the *same*
request as a *different* identity and comparing what comes back. gatecrash is built around
that idea rather than being a generic web scanner pointed at a JSON endpoint: give it two
sets of credentials and it replays your collection across them, then reports what let it
through, with the exact requests that prove it.

```bash
gatecrash init > identities.yaml           # fill in an admin and two users' tokens
gatecrash scan -c api.postman_collection.json -e prod.postman_environment.json \
               --target https://api.example.com -i identities.yaml -o ./out
```

Covers all ten OWASP API Security Top 10 (2023) categories — honestly, including saying
which two no scanner can decide for you. 27 checks, two dependencies, one command.

## Install

```bash
pip install -r requirements.txt        # requests + pyyaml, nothing else
pip install -e .                       # optional: puts `gatecrash` on your PATH
```

Python 3.9+. Without the editable install, run it as `python -m gatecrash`.

## Inputs

| Input | Flag | Notes |
| --- | --- | --- |
| Postman collection v2.0 / v2.1 | `-c file.json` | folders, `{{variables}}`, raw/urlencoded/formdata/GraphQL bodies |
| Postman environment | `-e env.json` | supplies the variables |
| OpenAPI 3.x / Swagger 2.0 | `-c spec.yaml` | JSON or YAML; examples, schemas and `$ref` are resolved to build real request bodies |
| Endpoint list | `-c urls.txt` | one `METHOD /path` or URL per line |
| Single URL | `--url https://…` | repeatable, with `-X METHOD` |

Format is auto-detected. `--target https://host` rebases every endpoint onto the host you
are actually testing, so a collection full of `{{baseUrl}}` pointing at production can be
run against staging without editing it. `--var key=value` overrides any unresolved variable.

## Identities — the part that matters

Authorisation bugs need more than one identity. `gatecrash init` writes a template:

```yaml
scope:
  - api.example.com          # requests to anything else are refused

primary: admin             # baseline as the most privileged caller

identities:
  - name: admin
    role: admin              # or an explicit number: privilege: 3
    headers:
      Authorization: "Bearer ${ADMIN_TOKEN}"

  - name: userA
    role: user
    headers:
      Authorization: "Bearer ${USER_A_TOKEN}"   # read from the environment
    owns: ["1001"]           # object IDs this user legitimately owns

  - name: userB
    role: user
    headers:
      Authorization: "Bearer ${USER_B_TOKEN}"
    owns: ["1002"]

  - name: anonymous
    role: anonymous          # added automatically if you omit it
```

Two things here are worth the five minutes they cost:

- **`owns`** is the difference between a BOLA finding reported as *probable* and one
  reported as *firm* with the object ID named in the evidence. It also stops the scanner
  mistaking a user's own object for someone else's.
- **An `admin` identity** is what makes API5 testable at all — see the coverage section
  below. Without a privilege gradient the tool can only guess from path names, and says so
  in the report.

For a quick look you can skip the file entirely: `--token "$TOKEN"` or `-H 'X-API-Key: …'`.
You lose the cross-user and cross-role checks, which is most of the value.

## Profiles

| Profile | What it does |
| --- | --- |
| `passive` | Sends exactly one request per endpoint — the collection's own — and analyses the responses. Safe against production. |
| `safe` *(default)* | Adds non-destructive active checks: credential stripping, cross-user and cross-role replay, mass assignment, SSRF, open redirect, CORS, rate limiting, pagination, shadow API versions. |
| `aggressive` | Adds ID enumeration, management-surface probing (`/.env`, `/actuator/env`, `/v3/api-docs`, …), request size limits and expensive-query probing. |

`PUT`, `PATCH` and `DELETE` are **blocked in every profile** unless you pass
`--allow-destructive`; blocked requests are recorded in the report rather than sent.
`--safe-methods-only` narrows the scan to `GET`/`HEAD`/`OPTIONS`.

## OWASP API Security Top 10 (2023) coverage

Every finding is tagged with its category, so the HTML and Markdown reports group by
API1–API10 for the client writeup. Coverage is **not** uniform, and the table says so —
two categories are not decidable by any scanner, and the tool treats them as inventory
and manual-test scaffolding rather than pretending to prove them.

| | Category | Depth | Checks |
| --- | --- | --- | --- |
| **API1** | Broken Object Level Authorization | Automated | `authz.bola`, `authz.id_enumeration` |
| **API2** | Broken Authentication | Automated | `auth.missing_enforcement`, `jwt.forgery`, `jwt.static` |
| **API3** | Broken Object Property Level Authorization | Automated | `authz.mass_assignment`, `passive.secrets`, `passive.pii` |
| **API4** | Unrestricted Resource Consumption | Automated | `misconfig.rate_limit`, `misconfig.pagination`, `misconfig.payload_limits`, `misconfig.expensive_query` |
| **API5** | Broken Function Level Authorization | Automated *(needs an admin identity)* | `authz.bfla`, `authz.bfla_coverage` |
| **API6** | Unrestricted Access to Sensitive Business Flows | **Manual scaffolding** | `bizflow.sensitive_flows` |
| **API7** | Server Side Request Forgery | Automated | `ssrf.injection` |
| **API8** | Security Misconfiguration | Automated | `misconfig.cors`, `misconfig.methods`, `misconfig.open_redirect`, `passive.headers`, `passive.transport`, `passive.verbose_errors`, `passive.internal_hosts` |
| **API9** | Improper Inventory Management | Automated | `inventory.api_versions`, `inventory.environment`, `misconfig.debug_surface` |
| **API10** | Unsafe Consumption of APIs | **Manual scaffolding** | `consumption.third_party` |

### What "manual scaffolding" means

**API6** depends on what the business loses when a flow is automated ten thousand times.
That is not visible on the wire. The check identifies every sensitive flow in the
collection, records which anti-automation controls were observable, and emits a specific
manual test plan — it does not attempt the abuse, and it does not claim a vulnerability.

**API10** is about how the API handles data it receives *from* other services. Whether the
upstream response is schema-validated, whether TLS is verified, whether redirects are
followed — none of it is observable from the client side. The check inventories the
integration surface and lists what to review.

Anyone claiming full automated coverage of these two is checking a box.

### API5 needs a privilege gradient

Authorisation intent cannot be read from a URL. `authz.bfla` walks *downward* from a more
privileged identity to a less privileged one, so **declare an admin identity and set
`primary: admin`**. Without one, the check falls back to flagging routes whose path looks
administrative, and `authz.bfla_coverage` puts a notice in the report saying coverage was
degraded — so a clean report never silently means "nothing was tested".

Where a route is reachable by both identities but is *not* named like an admin route, the
tool reports it separately at `tentative` confidence as a list to check against the
product's permission model — because many APIs correctly expose the same function to every
role, and a scanner cannot tell the difference.

`gatecrash checks` prints the live list. `--only authz.` and `--skip misconfig.` take
prefixes, so `--only jwt.` runs just the token work.

Findings carry a **confidence**: `firm` (the evidence is self-proving), `probable`
(response comparison says so), `tentative` (needs a human). Nothing above `tentative`
goes in a client report without you reading the evidence first.

## Output

`-o DIR` writes three files per run:

- **HTML** — filterable by severity and free text, every finding expanding to the raw
  request/response pairs behind it. Self-contained, no network access needed to view.
- **JSON** — one object per finding with full evidence, for diffing between retests or
  feeding a pipeline.
- **Markdown** — collapsible evidence blocks, ready to paste into engagement notes.

`--fail-on high` exits `2` when something at that severity or worse is found, for CI.

## Safety

### Read this before pointing it at a client

**`POST` is sent by default.** `PUT`, `PATCH` and `DELETE` are blocked, but a collection's
`POST` requests are replayed — at baseline, twice more by the credential checks, and once
more with injected properties by the mass-assignment check. A `POST /users` in the
collection therefore creates roughly **3 records per run**. That is inherent to testing a
creation endpoint at all; if you do not want it, use `--safe-methods-only`.

Always start with `--dry-run`, which prints the scope, every endpoint, which of them will
receive state-changing requests, and the checks that would run — without sending anything:

```bash
gatecrash scan -c api.postman_collection.json --target https://api.example.com --dry-run
```

Recommended progression on a client engagement:

| Stage | Command | Effect |
| --- | --- | --- |
| 1. Plan | `--dry-run` | sends nothing |
| 2. Staging | `--profile safe` | full active suite where mistakes are cheap |
| 3. Production, first pass | `--profile passive` | exactly one request per endpoint |
| 4. Production, read-only active | `--safe-methods-only` | no writes at all |
| 5. Production, full | `--profile safe` | only with the client's sign-off on the write list |

### What the tool enforces

- **Scope allowlist.** Every request is checked against `--scope` / the identity file's
  `scope` before it leaves. Anything else raises rather than sends. Scope defaults to the
  hosts found in your inputs and is printed for confirmation before the scan starts.
- **`PUT`/`PATCH`/`DELETE` off by default**, as above; blocked attempts are logged in the
  report rather than sent.
- **The burst probe will not touch anything that creates or sends.** `misconfig.rate_limit`
  sends 25 requests to one endpoint. It only ever picks a `GET`/`HEAD`, or a `POST` whose
  path is clearly authentication (`/login`, `/auth/token`, `/password/reset`). Endpoints
  matching orders, payments, invites, messages, uploads, registration and similar are
  excluded outright — bursting one would mean 25 real records or emails. `--rate-limit-burst 0`
  disables the check entirely.
- **Request budget and rate limit.** `--rps` (default 8) and `--max-requests`
  (default 20000) bound the traffic.
- **Proxy support.** `--proxy http://127.0.0.1:8080` puts the whole scan through Burp or
  ZAP so you have your own record of every request.
- **JWT key recovery is offline.** Candidate secrets are tested against the signature
  locally; the target sees nothing.
- **`--redact`** masks credential header values in the reports. Without it, every evidence
  pair contains the live bearer token you scanned with — fine for your own notes, not for
  a file you hand to the client.

### What it does not protect you from

- **Detection.** The `aggressive` profile requests `/.env`, `/actuator/env` and similar, and
  every profile sends `TRACE` and unusual `Origin` headers. If the client has a WAF or a SOC,
  warn them or they will page someone.
- **Side effects it cannot predict.** The tool has no idea that `POST /api/sync` triggers a
  billing run. Read the `--dry-run` write list against your knowledge of the API.
- **Field maturity.** This is version 1.0, verified against a purpose-built vulnerable API and
  a hardened control. It has not been run against a broad range of real-world APIs. Treat
  early runs on a client as something to supervise, not fire-and-forget.

## Try it

A deliberately vulnerable API is included:

```bash
python examples/vulnerable_api.py &                # 127.0.0.1:5099

login() { curl -s -XPOST localhost:5099/api/login \
  -H 'Content-Type: application/json' -d "{\"username\":\"$1\"}" | jq -r .token; }
export ADMIN_TOKEN=$(login carol)                  # admin - enables the API5 checks
export USER_A_TOKEN=$(login alice)
export USER_B_TOKEN=$(login bob)

gatecrash scan -c examples/vulnerable_api.postman_collection.json \
               -e examples/env.demo.postman_environment.json \
               -i examples/identities.demo.yaml \
               --var token="$ADMIN_TOKEN" \
               --profile aggressive -o ./out -y
```

That finds 42 issues across all ten OWASP API categories, including the seeded BOLA,
the mass assignment, SSRF via `file://`, the open redirect, the still-live `v1` API, the
unsigned-JWT acceptance and the recoverable signing key.

Comment the `admin` identity out of `examples/identities.demo.yaml` and re-run to see the
other half of the story: the API5 findings collapse and `authz.bfla_coverage` appears in
the report to tell you why.

(Leaving the identity in place but *unsetting* `ADMIN_TOKEN` is a hard error, not a
degraded scan — a credential that expands to the literal string `${ADMIN_TOKEN}` would
draw 401s that look exactly like correctly enforced access control, so the run would
appear clean while testing nothing.)

## Tests

```bash
python -m unittest discover -s tests
```

Includes a false-positive control: the same collection run against a hardened build of
the demo API drops from 42 findings to 5, with no critical or high false positives. The
control is what catches precision bugs — it has already caught a JWT check that reported
a valid token as forged (base64 aliasing in the signature mutation), a BOLA check that
accused a user of reading their own object, and probe parameters that were appended
rather than replaced and so never reached the application.

## Extending it

A check is one class in `gatecrash/checks/`:

```python
from .base import Check, register

@register
class MyCheck(Check):
    id = "custom.my_check"
    name = "Something worth reporting"
    severity = "high"
    owasp = "API1"
    profiles = ("safe", "aggressive")

    def applies(self, endpoint):
        return endpoint.method == "POST"

    def run(self, endpoint, baseline):
        ex = self.ctx.replay(endpoint, self.ctx.primary,
                             headers={"X-Test": "1"}, note="what this proves")
        if ex.status == 200:
            yield self.finding(endpoint, "Title", "Why it matters.", [baseline, ex],
                               confidence="firm", evidence_summary="one line for the report")
```

`self.ctx.replay()` is the only way to send a request — it enforces scope, throttling and
evidence capture. Import the module in `gatecrash/checks/__init__.py` and it appears in
`gatecrash checks` and in every profile you listed.

## Licence

MIT. Use it only against systems you are authorised to test.
