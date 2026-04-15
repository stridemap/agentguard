# AgentGuard — Migration Guide

A product by [Stridemap Labs LLC](https://stridemap.ai) — AI Security for the Enterprise.

## Upgrading from v1.5 to v2.0

### Breaking Changes

None. v2.0 is fully backward compatible with v1.5.

### New Features (opt-in)

| Feature | How to enable |
|---------|--------------|
| Multi-agent federation | `from agentguard.federation import FederationManager` |
| Policy marketplace | `from agentguard.marketplace import PolicyMarketplace` |
| S3 audit archival | `AGENTGUARD_ARCHIVAL_BACKEND=s3 AGENTGUARD_ARCHIVAL_BUCKET=your-bucket` |
| Multi-tenant SaaS | `from agentguard.multi_tenant import TenantManager` |
| SDK adapters | `from agentguard.sdk_adapters import govern_tool_call` |
| Policy v2 regex | Add `input_regex` / `output_regex` to YAML rules |
| Policy v2 OR mode | Add `match_mode: "or"` to YAML conditions |

### New Dependencies

v2.0 adds no new required dependencies. Optional dependencies:

```bash
pip install agentguard              # Core (same as v1.5)
pip install boto3                    # For S3 archival
pip install google-cloud-storage     # For GCS archival
pip install psycopg2-binary          # For PostgreSQL
pip install redis                    # For Redis queue
pip install authlib                  # For OIDC SSO
```

### New API Endpoints

All existing v1.5 endpoints remain unchanged. New endpoints added:

- `/federation/*` — 12 endpoints for multi-agent governance
- `/marketplace/*` — 5 endpoints for policy pack discovery
- `/tenants/*` — 10 endpoints for multi-tenant management
- `/compliance/*` — 5 endpoints for compliance reports

### New Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTGUARD_ARCHIVAL_BACKEND` | `local` | s3 / gcs / local |
| `AGENTGUARD_ARCHIVAL_BUCKET` | `audit-archive` | S3/GCS bucket name |
| `AGENTGUARD_TENANT_DB_PATH` | `data/tenants` | Base path for tenant DBs |
| `AGENTGUARD_ROLE_AGENT_MAP` | — | Tenant RBAC agent mapping |

### Upgrade Steps

```bash
pip install --upgrade agentguard==2.0.0
```

No configuration changes required. Existing policies, databases, and
interceptor configurations continue to work unchanged.

## Upgrading from v1.0 to v1.5

See CHANGELOG.md section [1.5.0] for details on SSO, RBAC, Kubernetes,
and compliance features added in v1.5.
