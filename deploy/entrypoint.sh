#!/bin/sh
# Seed mutable state onto the volume on first boot, then exec the gateway.
#
# The registry must be writable and must persist: it records which tool definitions this
# partner approved. Shipping it only inside the image would mean every redeploy silently
# reverted their approvals to whatever was baked at build time.
set -eu

: "${PORT:=8787}"
: "${MINIGATE_STATE_DIR:=/data}"

# The volume arrives owned by root, so this runs as root just long enough to hand the
# state directory to the unprivileged user, then drops privileges for the gateway itself.
if [ "$(id -u)" = "0" ]; then
  chown -R minigate:minigate "$MINIGATE_STATE_DIR" 2>/dev/null || true
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
