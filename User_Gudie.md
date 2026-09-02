# Using gatecrash — a walkthrough

A practical guide to running gatecrash on a real engagement, from "I've just been handed a
Postman collection" to "here are the confirmed findings". The [README](../README.md) is the
reference; this is the workflow.

---

## Contents

1. [The 60-second version](#the-60-second-version)
2. [Before you scan](#1-before-you-scan)
3. [Getting your inputs](#2-getting-your-inputs)
4. [Identities — the part that decides everything](#3-identities--the-part-that-decides-everything)
5. [The five-step scan flow](#4-the-five-step-scan-flow)
6. [Reading the report](#5-reading-the-report)
7. [Confirming each finding class by hand](#6-confirming-each-finding-class-by-hand)
8. [Retesting](#7-retesting)
9. [Recipes](#8-recipes)
10. [Troubleshooting](#9-troubleshooting)
11. [Flag reference](#10-flag-reference)

---

## The 60-second version

```bash
pip install -r requirements.txt && pip install -e .

gatecrash init > identities.yaml          # then fill in the tokens
export ADMIN_TOKEN=... USER_A_TOKEN=... USER_B_TOKEN=...

gatecrash scan -c api.postman_collection.json --target https://api.example.com \
               -i identities.yaml --dry-run          # see what it would send
gatecrash scan -c api.postman_collection.json --target https://api.example.com \
               -i identities.yaml -o ./out           # run it
open ./out/gatecrash-*.html
```

Everything below is why each of those flags is there.

---

## 1. Before you scan

**Authorisation.** gatecrash sends real attack traffic. Have written permission naming the
hosts you are about to put in `scope:`. The tool refuses to touch anything outside that list,
which is a safety net, not a substitute.

**Tell the client's ops team.** The `aggressive` profile requests `/.env`, `/actuator/env`
and similar, and every profile sends `TRACE` and unusual `Origin` headers. If they have a
WAF or a SOC, someone gets paged. Ten minutes of warning saves an incident call.

**What you need before you start:**

| | Why |
|---|---|
| A Postman collection or OpenAPI spec | The endpoint list. Without it, the tool has nothing to test. |
| Credentials for **two** ordinary users | Unlocks BOLA — the highest-value check. |
| Credentials for **one admin** | Unlocks BFLA. Without it API5 coverage is degraded, and the report says so. |
| Object IDs each user owns | Turns BOLA findings from *probable* into *firm*. |
| ~15 minutes | Mostly spent collecting the above. The scan itself takes 2–5 minutes. |

---

## 2. Getting your inputs

### From Postman

Export the collection: **right-click the collection → Export → Collection v2.1 → Save**.
Do the same for the environment (**Environments → ⋯ → Export**) if the collection uses
`{{variables}}`.

```bash
gatecrash scan -c api.postman_collection.json -e prod.postman_environment.json \
               --target https://api.example.com -i identities.yaml -o ./out
```

`--target` rebases every endpoint onto the host you're actually testing, so a collection
full of `{{baseUrl}}` pointing at production can be run against staging without editing it.

Any variable the environment doesn't resolve gets a placeholder and a warning. Override
individual ones with `--var key=value`.

### From an OpenAPI / Swagger spec

```bash
gatecrash scan -c openapi.yaml --target https://api.example.com -i identities.yaml -o ./out
```

JSON or YAML, OpenAPI 3.x or Swagger 2.0. Request bodies are built from `example`,
`examples`, `default`, `enum` and the schema itself, with `$ref`s resolved — so POST bodies
are realistic rather than empty.

### From a plain list, or a single URL

```bash
cat > endpoints.txt <<'EOF'
GET  /api/v2/users/1001
POST /api/v2/orders
GET  https://api.example.com/api/v2/health
EOF

gatecrash scan -c endpoints.txt --target https://api.example.com -i identities.yaml -o ./out
gatecrash scan --url https://api.example.com/api/v2/orders -X GET --token "$TOKEN" -o ./out
```

### What to do if you have neither

If the client can't produce a collection, capture one: proxy the app through Burp or Postman
while you click through every feature, then export. Ten minutes of clicking gives a better
endpoint list than any spec, because it reflects what the app actually calls.

---

## 3. Identities — the part that decides everything

This is where the value is. Everything else gatecrash does, a generic scanner also does.
The authorisation checks need to make *the same request as different people* and compare.

### Getting the tokens

Most APIs: call the login endpoint.

```bash
login() {
  curl -s -X POST https://api.example.com/api/login \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jq -r .token
}

export ADMIN_TOKEN=$(login admin@example.com 'AdminPass1')
export USER_A_TOKEN=$(login alice@example.com 'Passw0rd!')
export USER_B_TOKEN=$(login bob@example.com   'Passw0rd!')
```

If login is SSO or otherwise awkward, log in as each user in a browser, open **DevTools →
Network**, click any authenticated API call, and copy the `Authorization` header value.

### Finding out what each user owns

Call an endpoint that returns the current user and note the ID:

```bash
curl -s https://api.example.com/api/me -H "Authorization: Bearer $USER_A_TOKEN" | jq '.id'
```

Do it for both users. Those two IDs go in the `owns:` lists. This is the single highest-value
two minutes in the whole setup — it's the difference between *"userB reached an object"* and
*"userB read the record belonging to userA, object 1001, here is the response"*.

### Writing the file

```bash
gatecrash init > identities.yaml
```

Then edit:

```yaml
# Hosts this scan is authorised to touch. Anything else is refused before it is sent.
scope:
  - api.example.com
  # - "*.staging.example.com"     # wildcards allowed

# Baseline as the most privileged identity so BFLA can walk downward from it.
primary: admin

identities:
  - name: admin
    role: admin                   # or an explicit number: privilege: 3
    headers:
      Authorization: "Bearer ${ADMIN_TOKEN}"

  - name: userA
    role: user
    headers:
      Authorization: "Bearer ${USER_A_TOKEN}"
    owns: ["1001"]                # object IDs this user legitimately owns

  - name: userB
    role: user
    headers:
      Authorization: "Bearer ${USER_B_TOKEN}"
    owns: ["1002"]

  - name: anonymous
    role: anonymous               # added automatically if you omit it
```

**Tokens are read from the environment**, so this file is safe to keep alongside your
engagement notes. If a variable isn't exported, gatecrash **stops with an error** rather than
sending the literal string `${ADMIN_TOKEN}` as a credential — that would draw 401s
indistinguishable from correctly enforced access control, and the run would look clean while
testing nothing.

### Other auth schemes

```yaml
  - name: userA
    role: user
    headers:
      X-API-Key: "${USER_A_KEY}"           # API key header
    cookies:
      session: "${USER_A_SESSION}"         # cookie session
    query:
      access_token: "${USER_A_TOKEN}"      # token in the query string
```

### The quick-and-dirty version

For a first look, skip the file:

```bash
gatecrash scan -c api.postman_collection.json --token "$TOKEN" -o ./out
gatecrash scan -c api.postman_collection.json -H 'X-API-Key: abc123' -o ./out
```

You lose every cross-user and cross-role check, which is most of the point. Fine for a smoke
test, not for an engagement.

---

## 4. The five-step scan flow

Run these in order. Each one earns the right to run the next.

### Step 1 — Dry run: see what it would do

```bash
gatecrash scan -c api.postman_collection.json --target https://api.example.com \
               -i identities.yaml --dry-run
```

Sends **nothing**. Prints the scope, the endpoint count by method, every endpoint that would
receive a state-changing request, and the checks that would run.

**Read the write list against what you know about the API.** gatecrash has no idea that
`POST /api/sync` kicks off a billing run. This is the moment to catch that.

### Step 2 — Passive: one request per endpoint

```bash
gatecrash scan -c api.postman_collection.json --target https://api.example.com \
               -i identities.yaml --profile passive -o ./out
```

Sends exactly the collection's own requests, once each, and analyses the responses. Nothing
extra, no probes. Safe to point at production.

This alone finds exposed secrets, PII in bulk, stack traces, cleartext HTTP, JWT weaknesses
(the key recovery is done offline against the signature — the target never sees it) and
header problems.

### Step 3 — Safe: the full active suite

```bash
gatecrash scan -c api.postman_collection.json --target https://api.example.com \
               -i identities.yaml --profile safe -o ./out
```

The default. Adds credential stripping, cross-user replay (BOLA), cross-role replay (BFLA),
mass assignment, SSRF, open redirect, CORS, rate limiting, pagination and shadow API
versions.

`PUT`, `PATCH` and `DELETE` are blocked unless you pass `--allow-destructive`; blocked
attempts are recorded in the report rather than sent.

**`POST` is sent.** A `POST /users` in your collection gets replayed by several checks and
will create roughly three records. That's inherent to testing a creation endpoint. If the
client can't tolerate it:

```bash
gatecrash scan ... --safe-methods-only        # GET/HEAD/OPTIONS only, zero writes
```

### Step 4 — Aggressive: enumeration and management surfaces

```bash
gatecrash scan -c api.postman_collection.json --target https://api.example.com \
               -i identities.yaml --profile aggressive -o ./out
```

Adds ID enumeration, `/.env` and `/actuator` probing, request size limits and expensive-query
testing. This is the one that trips WAFs — save it for a window when someone's expecting it.

### Step 5 — Confirm out-of-band SSRF

If step 3 or 4 reported a blind SSRF candidate, re-run that check with a collaborator domain:

```bash
gatecrash scan -c api.postman_collection.json --target https://api.example.com \
               -i identities.yaml --only ssrf. \
               --oast-domain abc123.oast.fun -o ./out
```

gatecrash delivers the payload; **you** check your Collaborator/interactsh for the
interaction. It can't see your collaborator, so it reports the payload as delivered and
leaves the verdict to you.

---

## 5. Reading the report

Three files land in `-o`:

- **`gatecrash-<timestamp>.html`** — self-contained, filterable, every finding expands to the
  raw request/response pairs. This is the one you actually work from.
- **`gatecrash-<timestamp>.json`** — machine-readable, for diffing between retests.
- **`gatecrash-<timestamp>.md`** — collapsible evidence blocks, for pasting into notes.

### Triage order

Every finding carries a **severity** *and* a **confidence**. Work the grid, not the severity
column alone:

| | `firm` | `probable` | `tentative` |
|---|---|---|---|
| **critical / high** | **Start here.** Evidence is self-proving — read it, screenshot it, write it up. | Verify by hand, then write up. | Verify before you believe it. |
| **medium / low** | Write up in bulk. | Verify if it matters to the narrative. | Usually a checklist item, not a finding. |

What the confidences mean:

- **`firm`** — the evidence proves itself. A metadata endpoint's contents came back; the
  signing key verifies the signature; an invalid token got a 200.
- **`probable`** — inferred from comparing responses. Usually right, occasionally a shared
  resource that both identities are meant to see.
- **`tentative`** — a candidate for you to judge. The API6 business-flow list and the
  "confirm intent" BFLA list live here by design.

**Nothing above `tentative` goes in a client report without you reading the evidence first.**

### Two findings that are notices, not vulnerabilities

- **`authz.bfla_coverage`** — appears when you didn't supply an admin identity, to tell you
  API5 coverage was degraded. If you see this, a clean API5 result means very little.
- **`consumption.third_party`** / **`bizflow.sensitive_flows`** — inventories and manual test
  plans for API10 and API6. They're scaffolding for your own testing, not claims.

---

## 6. Confirming each finding class by hand

Scanner evidence is a starting point. Here's how to turn each into something you'd defend in
a report.

### BOLA (`authz.bola`) — critical

The report names the object, the owner and the attacker. Confirm by hand:

```bash
# Read the object as its owner
curl -s https://api.example.com/api/users/1001 -H "Authorization: Bearer $USER_A_TOKEN"
# Read the same object as someone else
curl -s https://api.example.com/api/users/1001 -H "Authorization: Bearer $USER_B_TOKEN"
```

Identical bodies = confirmed. Then establish the blast radius: does it work for *any* ID, or
just this one? Can an unauthenticated caller do it? Does the write side (`PUT`/`PATCH`) have
the same hole? That last question needs `--allow-destructive` or a manual request.

### BFLA (`authz.bfla`) — critical/high

Two flavours in the report. The **administrative** one lists routes named like admin
functions that a normal user reached — usually a real finding, confirm and write up. The
**"confirm intent"** one lists routes both roles reached where the path gives no clue.
Check that list against the client's intended permissions model; anything that should have
been admin-only is a genuine finding, the rest you dismiss.

### JWT (`jwt.forgery`, `jwt.static`) — critical

If the signing key was recovered, mint your own token to demonstrate impact:

```bash
python3 - <<'PY'
import base64, hashlib, hmac, json
secret = "secret"                      # from the finding
b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
h = b64(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
p = b64(json.dumps({"sub":"1","role":"admin"}).encode())
sig = b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
print(f"{h}.{p}.{sig}")
PY
```

Then use it against an admin endpoint. That single screenshot is worth more than the whole
finding description.

### SSRF (`ssrf.injection`) — critical

`firm` means content from the server's own network came back — done, write it up. `probable`
means blind: confirm with `--oast-domain`, or by timing an open internal port against a
closed one. Then find out how far it reaches: cloud metadata is the prize, but internal
service enumeration is often the more useful demonstration.

### Mass assignment (`authz.mass_assignment`) — high

The report shows which injected properties came back on the persisted object. Confirm the
change *stuck* — re-read the object in a separate request. A field echoed in the response but
not saved is a much weaker finding.

### Business flows (`bizflow.sensitive_flows`) — API6

This is your manual to-do list. For each flow: complete it by hand and capture the full
request sequence, replay it with a fresh identity and no browser, run it concurrently against
the same object to look for races, then work out the per-attempt cost to an attacker versus
the loss to the business. That last number is the finding.

---

## 7. Retesting

Finding IDs are stable across runs, so a retest is a diff.

```bash
# after the client's fixes
gatecrash scan -c api.postman_collection.json --target https://api.example.com \
               -i identities.yaml -o ./retest

OLD=./out/gatecrash-*.json
NEW=./retest/gatecrash-*.json

# fixed since the first scan
jq -r --slurpfile new $NEW '[$new[0].findings[].id] as $n
  | .findings[] | select(.id as $i | $n | index($i) | not)
  | "FIXED     \(.severity)  \(.title)"' $OLD

# new or regressed
jq -r --slurpfile old $OLD '[$old[0].findings[].id] as $o
  | .findings[] | select(.id as $i | $o | index($i) | not)
  | "NEW       \(.severity)  \(.title)"' $NEW
```

Keep the JSON from every scan with the engagement notes. It's the cheapest possible evidence
trail for "this was fixed on date X".

---

## 8. Recipes

**Record everything in Burp.** Route the whole scan through your proxy so you have your own
copy of every request, and can replay anything by hand:

```bash
gatecrash scan ... --proxy http://127.0.0.1:8080 -k
```

**Go gently against production.**

```bash
gatecrash scan ... --profile passive --rps 2 --workers 2
```

**Skip the burst probe entirely** (the only check that deliberately sends volume):

```bash
gatecrash scan ... --rate-limit-burst 0
```

**Run one family of checks.** `--only` and `--skip` take prefixes:

```bash
gatecrash scan ... --only authz.          # just the authorisation work
gatecrash scan ... --only jwt.            # just the token work
gatecrash scan ... --skip misconfig.      # everything except misconfiguration
```

**Share the report with the client** without leaking the token you scanned with:

```bash
gatecrash scan ... --redact
```

**In CI**, fail the build on high or worse:

```bash
gatecrash scan -c openapi.yaml --target https://staging.internal \
               -i identities.yaml --profile safe --fail-on high -o ./out -y
# exit 0 = clean, 2 = something at that severity or worse, 1 = the scan itself failed
```

`-y` skips the confirmation prompt — necessary in CI, and it's already skipped automatically
when stdin isn't a terminal.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `environment variable ${X} is not set` | Identity file references a token you didn't export | `export X='<token>'` — this is deliberately fatal, see [§3](#3-identities--the-part-that-decides-everything) |
| `every endpoint was filtered out before testing` | Scope doesn't match the target's host | Add the host to `scope:` or pass `--scope api.example.com` |
| `no usable endpoints were parsed` | Wrong file, or a collection whose URLs are all unresolved variables | Pass the environment with `-e`, or override with `--var baseUrl=https://…` |
| Everything is 401 / no findings | Tokens expired mid-scan | Re-mint them and re-run; API tokens often live 15 minutes |
| Findings look thin, `authz.bfla_coverage` in the report | No admin identity | Add one and set `primary: admin` |
| BOLA says *probable*, not *firm* | No `owns:` declared | Add the object IDs each user owns |
| Scan is very slow | Default is 8 req/s | Raise `--rps` — but ask the client first |
| Getting blocked or rate-limited partway | WAF noticed | Lower `--rps`, drop to `--profile passive`, or get allow-listed |
| Duplicate records created in the client's system | `POST`s in the collection are replayed | `--safe-methods-only`, or `--profile passive` |
| Report is enormous | Every response body is kept as evidence | Normal — the HTML is self-contained and filterable; use the JSON for tooling |

---

## 10. Flag reference

```
INPUTS
  -c, --collection FILE     Postman collection, OpenAPI spec, or endpoint list (repeatable)
  -e, --env FILE            Postman environment supplying {{variables}}
      --url URL             test a single URL (repeatable)
  -X, --method METHOD       HTTP method for --url (default GET)
      --target URL          base URL of the system under test; rebases every endpoint
      --var K=V             override a collection variable or spec parameter (repeatable)

CREDENTIALS
  -i, --identities FILE     YAML identity profiles — see `gatecrash init`
  -H, --header 'K: V'       header sent with every request (repeatable)
      --token TOKEN         shorthand for -H 'Authorization: Bearer <TOKEN>'

BEHAVIOUR
  -p, --profile NAME        passive | safe (default) | aggressive
      --only CHECK          run only these check ids (prefix match, repeatable)
      --skip CHECK          skip these check ids (prefix match, repeatable)
      --scope HOST          host the scan may touch; '*.example.com' allowed (repeatable)
      --allow-destructive   permit PUT/PATCH/DELETE (off by default)
      --safe-methods-only   restrict to GET/HEAD/OPTIONS
      --rate-limit-burst N  requests used by the rate-limit probe (0 disables; default 25)
      --jwt-wordlist FILE   extra candidate secrets for offline JWT key recovery
      --oast-domain DOMAIN  collaborator domain for blind SSRF confirmation
      --max-payload-kb N    size of the oversized-parameter probe (default 64)
  -n, --dry-run             show the plan and exit without sending anything
      --redact              mask credential values in the reports
  -y, --yes                 skip the scope confirmation prompt

NETWORK
      --rps N               max requests per second (default 8)
  -w, --workers N           concurrent workers (default 6)
      --timeout SECONDS     per-request timeout (default 15)
      --max-requests N      hard request budget for the run (default 20000)
      --proxy URL           route everything through a proxy, e.g. Burp
  -k, --insecure            do not verify TLS certificates

OUTPUT
  -o, --out DIR             report directory (default ./gatecrash-report)
  -f, --format LIST         comma-separated: html,json,md (default all three)
      --fail-on SEVERITY    exit 2 if a finding at this severity or worse is found
  -v, --verbose             repeat for debug logging
  -q, --quiet               only print report paths
```

Subcommands: `scan` (default), `checks` (list every check and its profile), `init` (print a
starter identity file).

---

## Practising on something safe

A deliberately vulnerable API ships with the repo. Use it to learn the workflow before you
point gatecrash at anything real:

```bash
python examples/vulnerable_api.py &                # 127.0.0.1:5099

login() { curl -s -XPOST localhost:5099/api/login \
  -H 'Content-Type: application/json' -d "{\"username\":\"$1\"}" | jq -r .token; }
export ADMIN_TOKEN=$(login carol)
export USER_A_TOKEN=$(login alice)
export USER_B_TOKEN=$(login bob)

gatecrash scan -c examples/vulnerable_api.postman_collection.json \
               -e examples/env.demo.postman_environment.json \
               -i examples/identities.demo.yaml \
               --var token="$ADMIN_TOKEN" \
               --profile aggressive -o ./out -y
```

42 findings across all ten OWASP API categories. Open the HTML report and practise the triage
grid on it — every finding class in [§6](#6-confirming-each-finding-class-by-hand) is
represented.
