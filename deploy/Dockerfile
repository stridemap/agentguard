# MiniGate remote gateway — one image, one deployment per partner.
#
# Build context is the repo root:
#     docker build -f deploy/Dockerfile -t minigate .
#
# The spaCy model is baked in deliberately. It is 445 MB; downloading it at boot would
# turn a ~2s cold start into minutes and would fail entirely on a host without egress to
# the model CDN. Baking it also makes the image content-addressable — two deployments of
# the same tag scan with the same model.

FROM python:3.13-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# Presidio pulls in packages with C extensions; the compiler is needed to build them and
# is dropped from the runtime stage below.
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc g++ \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# The model is downloaded before any source is copied, so it forms a layer that editing
# code never invalidates. It is the only slow step in the build — 445 MB.
RUN pip install --no-cache-dir spacy \
 && python -m spacy download en_core_web_lg

# Then the package itself, installed properly rather than as an editable stub. Installing
# from partial source produces a site-packages `minigate` containing only __init__.py,
# which then shadows the real source at runtime — a ModuleNotFoundError at boot.
COPY pyproject.toml README.md ./
COPY agentguard/ agentguard/
COPY minigate/ minigate/
# The [postgres] extra is not optional for a hosted deployment. Without psycopg2 the
# store factory raises, create_sink swallows it, and the gateway comes up serving traffic
# with a NullSink — governing correctly while recording nothing.
RUN pip install --no-cache-dir ".[postgres]"

# ── runtime ──────────────────────────────────────────────────────────
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MINIGATE_LOG_LEVEL=INFO

# Never run the gateway as root: it terminates untrusted traffic from a vendor endpoint.
# gosu lets the entrypoint start as root purely to fix ownership of the mounted volume —
# platforms attach volumes owned by root, so a container that has already dropped to an
# unprivileged user cannot write to its own state directory — and then drop privileges
# before exec'ing the gateway itself.
RUN useradd --create-home --uid 10001 minigate \
 && apt-get update \
 && apt-get install -y --no-install-recommends gosu \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=build /usr/local/bin /usr/local/bin

WORKDIR /app

# Only data files land here. The code lives in site-packages, copied from the build stage
# — one installed copy, nothing at /app to shadow it.
COPY policies/ policies/
COPY deploy/minigate.hosted.yaml ./minigate.hosted.yaml

# The registry file and the lineage taint store are mutable state, so they live on the
# mounted volume rather than in the read-only image. Seeded on first boot by the entrypoint.
# The seed is an EMPTY registry, not a snapshot of anyone's approvals. Baking a
# particular partner's approved definitions into a shared image makes the image
# partner-specific and silently re-asserts stale approvals on every redeploy. A fresh
# deployment starts with nothing approved and is populated by `minigate registry sync`,
# which is the only step that records who reviewed what and when.
RUN mkdir -p /app/seed && printf 'version: 1\ntools: []\n' > /app/seed/minigate-registry.yaml
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && mkdir -p /data && chown minigate:minigate /data

EXPOSE 8787

# Liveness only. /healthz reports "degraded" without failing, because a gateway whose
# audit store is unreachable still governs traffic — restarting it would fix nothing and
# would drop live sessions.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8787\")}/healthz',timeout=4)"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
