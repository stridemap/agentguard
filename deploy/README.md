# Hosting MiniGate on Railway — one deployment per partner

One Docker image, one Railway service per partner, one shared Postgres. This is the
single-tenant shape on purpose: MiniGate has no tenant dimension, so isolation comes from
running separate services rather than from code that does not exist yet. See the note at
the bottom before considering anything else.

Everything here was verified locally in Docker against a mock MCP upstream and a real
Postgres before being written down.

## Files

| file | what it is |
|---|---|
| `Dockerfile` | Two-stage build. The 445 MB spaCy model is baked into the image. |
| `entrypoint.sh` | Seeds the registry onto the volume on first boot, then execs the gateway. |
| `minigate.hosted.yaml` | The config, templated on environment variables. |
| `railway.json` | Build and deploy settings, including the `/healthz` check. |

## Environment variables

| variable | required | notes |
|---|---|---|
| `PARTNER` | yes | Recorded as `client_id` on every audit event. |
| `PUBLIC_URL` | yes | The URL clients dial, e.g. `https://acme.mcp.stridemap.ai`. |
| `DATABASE_URL` | yes | Railway's Postgres plugin injects this. |
| `PORT` | injected | Railway sets it; the entrypoint passes it through. |
| `SERVER_NAME` | no | Default `linear`. Must match `registry sync --server-name`. |
| `UPSTREAM_URL` | no | Default `https://mcp.linear.app/mcp`. |
| `UPSTREAM_AS` | no | Default `https://mcp.linear.app`. |
| `REGISTRY_MODE` | no | Default `enforce`. Start a new partner at `observe`. |
| `MINIGATE_STATE_DIR` | no | Default `/data`. Mount a volume here. |

An unset variable with no default is a **startup error**, not an empty string. A gateway
advertising `public_url: ""` answers OAuth discovery with a URL no client can reach, and
that surfaces as a client-side auth loop far from its cause.

## Deploying

1. **Postgres.** Add the Postgres plugin to the Railway project. Create one database per
   partner — `CREATE DATABASE acme;` — and point that service's `DATABASE_URL` at it.
   Separate databases, not separate schemas: each needs its own `events` table so each
   gets its own hash chain, and Postgres advisory locks are database-scoped so partners
   do not serialise against each other on chain appends.

2. **Service.** New service from this repo, Dockerfile path `deploy/Dockerfile`. Set the
   variables above. Attach a volume mounted at `/data`.

3. **Deploy at `REGISTRY_MODE=observe` first.** Deploying straight into `enforce` against
   an unsynced registry serves *zero tools* — every definition is UNKNOWN — and the
   gateway looks broken rather than strict.

4. **Sync the registry**, from a machine that can reach the vendor, then push it to the
   volume. Capture the drift first — it is scenario 3's raw material and syncing destroys
   it:

   ```bash
   minigate registry diff --server-name linear --config minigate.yaml \
     | tee deploy/evidence/drift-$(date +%F).txt
   minigate registry sync --server-name linear --config minigate.yaml \
     --approved-by "<who approved it>"
   ```

   Then get it onto the volume. **Do not pipe it over `railway ssh`** — stdin redirection
   never terminates the session and the command hangs. Ship it in the image instead and
   let the entrypoint seed it:

   ```bash
   railway up --service minigate            # bakes the new registry into /app/seed
   railway ssh --service minigate "rm -f /data/minigate-registry.yaml"
   railway redeploy --service minigate --yes # entrypoint re-seeds from the new image
   railway ssh --service minigate "wc -l < /data/minigate-registry.yaml"
   ```

   **Order matters, and getting it wrong is silent.** The entrypoint seeds only when the
   file is absent — which protects an operator's edits from being reverted by a redeploy,
   but means a stale copy sticks. Worse, *any* action that restarts the service re-seeds
   from whatever image is current: deleting the file and then setting a variable will
   re-seed from the OLD image before the new one deploys. Build first, delete second,
   redeploy third, then verify the line count.

   Finally: `railway variables set --service minigate 'REGISTRY_MODE=enforce'`.

5. **Domain.** Add `<partner>.mcp.stridemap.ai` in Railway and set `PUBLIC_URL` to match.

6. **Check it.** `curl https://<partner>.mcp.stridemap.ai/healthz` must report
   `"status": "ok"`. See below if it says `degraded`.

## Where things live, and who can change them

| file | location | mutable at runtime |
|---|---|---|
| `minigate.hosted.yaml` | `/app/` — baked into the image | no |
| `policies/minigate.yaml` | `/app/policies/` — baked into the image | no |
| `minigate-registry.yaml` | `/data/` — on the volume | yes |
| `PARTNER`, `REGISTRY_MODE`, … | Railway environment | yes, on restart |

There is no `minigate.yaml` here — that is the local stdio config. `policy:` is resolved
against the config file's own directory, so `policies/minigate.yaml` means
`/app/policies/minigate.yaml`.

**Config and policy change by commit and redeploy:**

```bash
vim policies/minigate.yaml           # or deploy/minigate.hosted.yaml
railway up --service minigate
```

**Anything templated in the config changes without a rebuild:**

```bash
railway variables set --service minigate 'REGISTRY_MODE=observe'
```

**The registry changes over SSH**, as in step 4 above.

### Why policy is immutable and the registry is not

This asymmetry is deliberate. Policy is an intent you author; the registry is a record of
what a vendor was observed advertising, and it has to be updatable when that vendor ships
a change.

Keeping policy in the image means every change is a reviewed commit with history and
attribution, and rollback is `railway rollback`. There is no way to weaken a running
gateway without leaving a trace in git — which is the answer to "who can turn this off,
and would anyone know?"

The cost is that a one-line rule change needs a deploy. `PolicyEngine.start_hot_reload()`
already watches the policy file, so moving `policies/` onto the volume would give
edit-and-take-effect. Resist it for a security control: once policy is mutable at runtime
with no review trail, "what was the policy when this call was blocked?" stops having a
reliable answer. The audit chain records the decision, not the rule text that produced it.

## /healthz

Reports liveness **and** the two ways a healthy-looking process is not doing its job:

- `audit sink is NullSink` — the audit store could not be opened, so nothing is being
  recorded. Almost always a wrong or unreachable `DATABASE_URL`.
- `DLP disabled after a scanner error` — responses are no longer being redacted.

Both are deliberate fail-open behaviour and both are invisible from outside: the gateway
answers every request exactly as before. It returns **200 even when degraded**, because
this is liveness, not readiness — restarting the process would not fix an unreachable
database and would drop live sessions.

## Cost

Measured footprint is **~515 MB resident**, essentially all Presidio and spaCy. At
Railway's rates (≈$10/GB-month memory, ≈$20/vCPU-month, $0.15/GB-month volume) that is
roughly **$6.50 per partner per month**, plus ~$3 for the shared Postgres, on top of the
$20/month Pro plan which includes $20 of usage. One partner therefore costs the plan fee
and nothing more.

Cold start to first scan is **1.9 s**, so scale-to-zero is viable for bursty demo traffic
and brings ten partners back to the plan floor. That number depends on the model being
baked into the image — downloading 445 MB at boot would make it minutes.

## Verified locally

```bash
docker build -f deploy/Dockerfile -t minigate:local .
docker run -d --name minigate -p 8891:8891 -v mg:/data \
  -e PORT=8891 -e PARTNER=acme -e PUBLIC_URL=https://acme.mcp.stridemap.ai \
  -e DATABASE_URL=postgresql://... minigate:local

curl localhost:8891/healthz
curl -i -X POST localhost:8891/mcp/linear -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Confirmed in that harness: 401 with RFC 9728 `WWW-Authenticate`; discovery advertising the
*upstream's* authorization server; a bogus token relayed and rejected by the vendor rather
than by MiniGate; `tools/list` filtered; a deletion refused by MG-010; a result carrying an
injection payload withheld; events written to Postgres; and `minigate verify` returning
`is_valid: true`.

## Before adding a second partner

This is single-tenant. A second partner means a **second service**, not a second tenant on
this one. MiniGate cannot tell callers apart — the auth check is presence-only, because
passthrough OAuth deliberately leaves authorization to the vendor — so one instance has one
policy, one `client_id`, and one audit chain.

Two things in particular are unsafe to retrofit once partners are live:

- **The taint store** is shared by design and becomes a cross-tenant oracle: A reads a
  value, B writes it, B is blocked and told the source was `CONFIDENTIAL`. Namespace the
  hash by tenant before any shared deployment. `lineage.enabled` is `false` here for
  exactly this reason.
- **The audit chain** is global — one tip for the whole `events` table. Interleave two
  partners and neither can be handed a verifiable chain without the other's rows.

## Note on credentials

Passthrough means partner tokens transit this service. MiniGate mints, stores and refreshes
nothing — that is ADR-002 and it is a strong answer — but "in memory on our box" is not
"never touches us". Say so plainly to a partner rather than letting them discover it.
