# CheckYourself — ResonantOS add-on

The [CheckYourself](https://github.com/KyaniteLabs/checkyourself) production-readiness
check, packaged as a ResonantOS 2.0.0-alpha add-on. CheckYourself is a read-only
diagnostic for apps built with AI: it scans a project directory, detects the stack,
flags concrete risks (committed `.env` files, secret-shaped strings, dangerous sinks,
missing tests or CI) ranked P0–P3, scores findings 0–100 with explicit confidence,
and ranks the remediation backlog. It inspects; it never modifies the scanned project.

The engine is vendored byte-identical under `vendor/` (Apache-2.0, with upstream
LICENSE and NOTICE preserved) and wrapped by a thin local service. The wrapper adds
no dependencies: Python 3.10+ standard library only.

## What it does

- `checkyourself.status` — service version, busy state, last scan id, scan-root boundary.
- `checkyourself.scan` — the check itself (upstream verbs `scan`/`diagnostic`): one
  read-only deterministic scan of a project directory under the scan root. Results
  are returned inline and persisted home-path-redacted under `var/<scan-id>/scan.json`.
- `checkyourself.score` — deterministic Production Reality Score from inline findings
  plus optional coverage; estimates without coverage are always labeled low confidence.
- `checkyourself.backlog` — complete remediation backlog + safest first approval batch.
- `checkyourself.validate` — validate an inline artifact against a bundled schema.
- `checkyourself.schema` — fetch a bundled JSON schema by name.

One scan at a time (409 while busy). Scans are confined to `CHECKYOURSELF_SCAN_ROOT`
(default: the service process working directory) — the same boundary as the upstream
MCP server; paths outside it are refused.

## Running it

    python3 server.py          # listens on http://127.0.0.1:4892 (the manifest entrypoint)

    curl -s http://127.0.0.1:4892/health
    curl -s -X POST http://127.0.0.1:4892/ -H 'Content-Type: application/json' \
      -d '{"method":"checkyourself.scan","params":{"project":"/path/to/project"}}'
    curl -s -X POST http://127.0.0.1:4892/ -H 'Content-Type: application/json' \
      -d '{"method":"checkyourself.score","params":{"findings":[...]}}'

Environment: `CHECKYOURSELF_SCAN_ROOT` (scan boundary), `CHECKYOURSELF_PORT` (dev
only — the manifest declares 4892). The service spawns no subprocesses, makes no
network calls, keeps no telemetry, and redacts home paths (your home directory
becomes `~`) in every response and in everything it persists under `var/`.
Secret-shaped strings found during scans are redacted by the engine before they
reach any output.

## Tests

    python3 -m unittest discover -s tests        # wrapper suite (28 tests)
    python3 -m unittest discover -s vendor/tests # upstream suite, unmodified
    sh run-validator-check.sh <path-to-2.0.0-alpha-clone>  # manifest vs the real validator

`vendor/` is hash-pinned to upstream; a wrapper test fails loudly if any vendored
file drifts. The vendored upstream suite runs the CLI by subprocess from the
vendored tree (upstream behavior, left unmodified).

## License

MIT for the wrapper (server.py, tests/, addon.json) — see LICENSE. The vendored
CheckYourself engine is Apache-2.0, Kyanite Labs — see `vendor/LICENSE` and
`vendor/NOTICE.md` (byte-identical to upstream).
