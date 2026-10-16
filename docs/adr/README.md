# Architecture Decision Records

One file per significant technical decision: the context that forced it, the choice
made, and the consequences accepted. Code records *what* was built; these record *why
the alternative was rejected*.

**Conventions**

- Filename: `NNN-short-kebab-title.md`, numbered sequentially, never reused.
- ADRs are immutable once `Accepted`. To change a decision, write a new ADR and mark the
  old one `Superseded by ADR-NNN`. The history is the point.
- Keep them to roughly one page. If it needs more, it is a design doc — link to it.
- Status is one of: `Proposed`, `Accepted`, `Superseded by ADR-NNN`, `Deprecated`.

Note: the rest of `docs/` is gitignored (private PDFs and specs). `docs/adr/` is
explicitly re-included in `.gitignore` because decision records must be version-controlled.

| ADR | Title | Status |
|-----|-------|--------|
| [001](001-no-model-channel-interception.md) | Govern at the MCP protocol layer; no TLS interception | Accepted |
| [002](002-oauth-passthrough.md) | OAuth passthrough, not a gateway-owned authorization server | Accepted |
