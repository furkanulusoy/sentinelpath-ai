# Threat Model

This document describes SentinelPath AI's assets, trust boundaries,
and accepted risks. It complements [SECURITY.md](SECURITY.md) (how to
report a vulnerability, and what has already been fixed) and
[ARCHITECTURE.md](ARCHITECTURE.md) (system design).

## Assets

- **Attack graph data** — the `AttackGraphSnapshot` built by the Graph
  Builder (`src/sentinelpath/graph_builder/`): hosts, users, and typed
  edges derived from observed network/auth activity. This is
  sensitive: it encodes real network topology and behavior patterns
  for an organization.
- **Prediction results** — `PredictionResult`, `RiskScore`, and the
  final `SentinelPathReport` (probabilities, risk scores, and
  recommendations tied to specific hosts). Disclosure of this data
  reveals which hosts an organization currently considers
  compromised/high-risk.
- **Source/input data** — raw `NormalizedEvent`s ingested from pcap
  captures, LANL-format auth/flow logs, or future collector adapters.
  These may contain hostnames, usernames, and traffic metadata.
- **Source code and configuration** — the codebase itself, and any
  operator-supplied configuration such as `asset_criticality_map`
  values (`src/sentinelpath/config/settings.py`,
  `SENTINELPATH_*` environment variables), which encode an
  organization's asset-criticality judgments.

There is currently no persistence layer (see README.md's "Known
Limitations"); all of the above live only in-process, for the
lifetime of a single pipeline run.

## Trust Boundaries

- **HTTP API caller — untrusted.** `POST /api/v1/predict` and
  `GET /health` (`src/sentinelpath/api/main.py`) accept requests from
  any caller that can reach the process; the API performs no
  authentication or authorization. Every field in the request body is
  treated as untrusted input and validated at the Pydantic schema
  boundary (`src/sentinelpath/api/schemas.py`) before entering the
  pipeline.
- **External dataset files — untrusted external input.** `.pcap`
  captures (`PcapFileCollector`) and LANL-format auth/flow log lines
  (`LANLAuthCollector`, `LANLFlowsCollector`) are external files that
  may be malformed, truncated, or (in an adversarial scenario)
  deliberately crafted to break the parser. These are parsed
  defensively: malformed lines/fields are logged and skipped rather
  than aborting the whole run or being trusted blindly.
- **The pipeline internals (Feature Extraction → Graph Builder →
  Attack Path Engine → Prediction Model → Risk Scoring →
  Recommendation → Reporting) are trusted relative to each other.**
  Once an event has crossed the Collector boundary as a
  `NormalizedEvent`, downstream stages assume it is well-formed
  (typed via the shared domain models in `src/sentinelpath/core/models.py`)
  — they do not re-validate it as if it were still adversarial input.
  This is a deliberate internal trust boundary: only the two entry
  points above (API caller, external dataset files) are treated as
  hostile.
- **The dashboard (browser) — trusted rendering of pipeline output,
  but the data it renders is not.** The static dashboard
  (`src/sentinelpath/static/dashboard/`) runs in an analyst's browser
  and renders values that ultimately trace back to the untrusted
  boundaries above (event content, technique IDs). It must treat all
  rendered values as data, never as markup — this is why the stored
  XSS issue in `app.js` (see SECURITY.md) mattered even though the
  dashboard itself is "trusted" code.

## Accepted Risks

- **The HTTP API has no authentication, and this is a deliberate
  accepted risk, not an oversight.** `src/sentinelpath/api/main.py`
  exposes `/api/v1/predict` and `/health` with no API key, session, or
  network-level access control. SentinelPath AI is designed for
  **local or trusted-network deployment only** — e.g. run on
  `localhost`, inside a lab environment, behind a VPN, or on an
  internal network segment with its own access controls. **Operators
  must not expose this API directly to the public internet or to an
  untrusted network without adding their own
  authentication/authorization layer (reverse proxy with auth, API
  gateway, mTLS, etc.) in front of it.** This tradeoff was made to
  keep the MVP focused on the prediction pipeline itself (see
  README.md's roadmap, Tier 6 — "API versioning and rate limiting" is
  explicitly listed as future production-hardening work, not yet
  done).
- **No rate limiting.** Follows from the above — a trusted-network
  deployment assumption means request volume is not currently
  defended against at the application layer.
- **Bounded, not zero, resource consumption.** The request-size caps
  (`max_length` on `events`/`known_hosts` in
  `src/sentinelpath/api/schemas.py`) and the `MAX_ENUMERATED_PATHS`
  budget in `src/sentinelpath/attack_path_engine/infrastructure/networkx_engine.py`
  (see SECURITY.md) reduce the worst case but do not guarantee a
  specific latency/memory ceiling on every possible graph shape. This
  is considered acceptable for the current trusted-network use case.

## Out of Scope

The following are explicitly **not** covered by this document and are
tracked separately, if at all:

- **Deployment/infrastructure hardening** — container/host OS
  hardening, network segmentation, TLS termination, secrets
  management, reverse-proxy/auth-gateway configuration. The Dockerfile
  already applies some baseline practices (multi-stage build,
  non-root user — see ADR 0012), but full deployment hardening is the
  responsibility of whoever operates SentinelPath AI in their
  environment.
- **Dependency supply-chain auditing / lockfiles.** `pyproject.toml`
  declares version-range dependencies; there is currently no lockfile,
  SBOM, or automated dependency/secret scanning in CI
  (`.github/workflows/ci.yml`). This is listed as future work in
  README.md's roadmap (Tier 2, item 4) and should be tracked and
  addressed independently of this document.
- **Model/data-poisoning attacks on the prediction pipeline itself**
  (e.g. an attacker deliberately shaping their own traffic to bias
  the Baseline Behavior or Prediction Model) — a real concern for a
  behavioral system like this one, but a research question distinct
  from the application-security scope of this document.
