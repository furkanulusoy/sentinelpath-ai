# Security Policy

## Supported Versions

SentinelPath AI is currently a research/prototype system (pre-1.0,
`0.1.0` on the `main` branch — see the "Project Status" section of
[README.md](README.md)). There is no released version history yet, so
only the latest commit on `main` is supported with security fixes.

| Version | Supported |
|---|---|
| `main` (latest) | :white_check_mark: |
| anything else | :x: |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security
vulnerabilities.

Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/furkanulusoy/sentinelpath-ai/security/advisories/new).
This repository has no separate security mailing list or dedicated
contact channel — GitHub Security Advisories is the intended and only
supported reporting path.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal input/request is ideal)
- The affected file(s)/endpoint(s), if known

We aim to acknowledge new reports within a reasonable timeframe and
will work with you on a fix and coordinated disclosure. As a small,
non-commercial project, there is no formal SLA.

## Known Security Posture

SentinelPath AI is a research/prototype attack-path-prediction engine,
not a hardened multi-tenant service. Operators should be aware of the
following before deploying it:

- **No built-in authentication on the HTTP API.** The FastAPI
  application (`src/sentinelpath/api/main.py`) exposes `/health` and
  `/api/v1/predict` with no authentication, authorization, or rate
  limiting. It is intended for **local or trusted-network use only**
  (e.g. behind a VPN, on `localhost`, or in an internal lab/CI
  environment) — see [THREAT_MODEL.md](THREAT_MODEL.md) for the full
  reasoning. Do not expose it directly to the public internet without
  adding your own authentication/authorization layer.
- **Input validation boundaries.** Request bodies are validated by
  Pydantic schemas (`src/sentinelpath/api/schemas.py`) with explicit
  size bounds (see the transparency section below). External dataset
  files (LANL auth/flows logs, `.pcap` captures) are parsed
  defensively — malformed lines are logged and skipped rather than
  crashing the pipeline — but these parsers are not hardened against
  adversarially crafted files beyond what is described here.
- **No persistence layer.** Pipeline state is in-memory only (see
  "Known Limitations" in README.md), so there is no data-at-rest
  exposure from the application itself.

## Transparency: Issues Found and Fixed

In the interest of transparency, the following security issues were
identified during internal review and have already been fixed on
`main`:

1. **Stored XSS in the dashboard via unescaped `innerHTML`.**
   `src/sentinelpath/static/dashboard/app.js` built table rows and
   recommendation list items by interpolating pipeline data
   (technique IDs, recommendation text, etc.) directly into
   `element.innerHTML` template strings. Since this data can
   ultimately originate from attacker-influenced event content,
   unsanitized values could execute arbitrary script in an analyst's
   browser. **Fix:** rewritten to build the DOM with
   `createElement`/`textContent` instead of `innerHTML`, so all
   rendered values are treated as text, never markup.

2. **Unbounded request body on `/api/v1/predict`.** `PredictRequest`
   in `src/sentinelpath/api/schemas.py` accepted an unbounded
   `events` list and an unbounded `known_hosts` list, allowing a
   caller to submit an arbitrarily large JSON body and force
   disproportionate processing/memory use. **Fix:** added
   `max_length=1000` on `events` and `max_length=200` on
   `known_hosts`.

3. **Algorithmic-complexity DoS via unbounded path enumeration.**
   `NetworkXAttackPathEngine.find_candidate_paths` in
   `src/sentinelpath/attack_path_engine/infrastructure/networkx_engine.py`
   consumed `networkx.all_simple_paths()` in full; on a dense graph
   the number of simple paths between two nodes can grow
   combinatorially even with a hop cutoff (this was independently
   observed at real scale — 2.3M candidate paths from a single start
   node — see ADR 0016), making the endpoint a CPU/memory exhaustion
   vector. **Fix:** introduced a `MAX_ENUMERATED_PATHS` budget (10,000)
   and enumerate paths via `itertools.islice` so the search always
   terminates.

4. **Unhandled parse exceptions on malformed external dataset lines.**
   The LANL dataset adapters
   (`src/sentinelpath/collector/infrastructure/lanl_auth_adapter.py`,
   `src/sentinelpath/collector/infrastructure/lanl_flows_adapter.py`)
   and the scan detector
   (`src/sentinelpath/discovery_detection/infrastructure/scan_detector.py`)
   parsed untrusted external file fields (timestamps, byte counts)
   without guarding against malformed values, so a single bad line in
   a multi-million-line external dataset could raise an unhandled
   exception and abort the whole ingestion run. **Fix:** malformed
   timestamp/byte-count fields are now caught (`try`/`except`), logged
   as a warning with the offending line number, and skipped, so
   ingestion continues.

If you find additional issues, please report them through the process
above rather than opening a public issue.
