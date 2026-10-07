#!/bin/sh
# Seed mutable state onto the volume on first boot, then exec the gateway.
#
# The registry must be writable and must persist: it records which tool definitions this
# partner approved. Shipping it only inside the image would mean every redeploy silently
# reverted their approvals to whatever was baked at build time.
set -eu

: "${PORT:=8787}"
: "${MINIGATE_STATE_DIR:=/data}"
: "${AUTH_MODE:=bridge}"

# Bridge mode stores live upstream credentials, sealed with this key. Coming up without
# it would mean either refusing every request or — far worse, if the check were ever
# relaxed — holding other people's access tokens in the clear. Fail here, loudly, where
# the cause is unambiguous, rather than at the first authorization hours later.
if [ "$AUTH_MODE" = "bridge" ] && [ -z "${MINIGATE_GRANT_KEY:-}" ]; then
  echo "minigate: AUTH_MODE=bridge requires MINIGATE_GRANT_KEY." >&2
  echo "minigate: generate one with" >&2
  echo "minigate:   python -c 'from minigate.bridge_sql_store import generate_key; print(generate_key())'" >&2
  echo "minigate: then set it on the service. Rotating it later invalidates every" >&2
  echo "minigate: stored grant and forces every partner to re-consent." >&2
  exit 1
fi

# The volume arrives owned by root, so this runs as root just long enough to hand the
# state directory to the unprivileged user, then drops privileges for the gateway itself.
if [ "$(id -u)" = "0" ]; then
  chown -R minigate:minigate "$MINIGATE_STATE_DIR" 2>/dev/null || true
fi

# In bridge mode the grants belong in Postgres alongside the audit chain: the volume is
# the wrong home for credentials that must survive a redeploy and be revocable centrally.
if [ "$AUTH_MODE" = "bridge" ] && [ -z "${MINIGATE_GRANT_URL:-}" ] && [ -n "${DATABASE_URL:-}" ]; then
  export MINIGATE_GRANT_URL="$DATABASE_URL"
fi

if [ ! -f "$MINIGATE_STATE_DIR/minigate-registry.yaml" ]; then
  echo "minigate: seeding registry into $MINIGATE_STATE_DIR" >&2
  cp /app/seed/minigate-registry.yaml "$MINIGATE_STATE_DIR/minigate-registry.yaml"
  [ "$(id -u)" = "0" ] && chown minigate:minigate "$MINIGATE_STATE_DIR/minigate-registry.yaml"
fi

RUN_AS="exec"
if [ "$(id -u)" = "0" ]; then
  RUN_AS="exec gosu minigate"
fi

# shellcheck disable=SC2086
$RUN_AS minigate serve \
  --config /app/minigate.hosted.yaml \
  --host 0.0.0.0 \
  --port "$PORT"
