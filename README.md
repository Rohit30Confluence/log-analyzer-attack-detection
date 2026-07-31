# Log Analyzer & Attack Detection

A Python toolkit for parsing Apache access logs and detecting common web
attacks — **brute force**, **SQL injection**, **XSS**, and **volume-based
anomalies** — from either a static log file (CLI) or a live ingestion
pipeline (FastAPI + Redis backend).

```
$ python cli.py --input data/sample_access.log --analyze
[+] Parsed 7 log entries.
[*] Running attack detection...
  -> Brute Force: 0 suspicious entries
  -> SQL Injection: 2 suspicious entries
  -> XSS: 1 suspicious entries
```

## Features

- **Log parsing** — Apache Common Log Format (CLF) and Combined Log Format,
  streamed line-by-line (no full-file load required).
- **Signature-based detection**:
  - Brute force — repeated 401/403 responses from one IP against *any*
    endpoint within a rolling time window.
  - SQL injection — pattern matching with percent-decoding, so `%20`-style
    encoding doesn't bypass detection.
  - XSS — script/event-handler pattern matching, also percent-decoded.
- **Anomaly detection** — leave-one-out z-score on per-IP request volume,
  flags IPs generating unusually high traffic relative to the rest of the
  batch.
- **Three ways to run it**: one-shot CLI, a FastAPI ingestion service backed
  by Redis for async processing, or a real-time streaming demo.

## Project structure

```
.
├── analyzer/                  # Core detection library
│   ├── parser.py              #   Log line -> structured dict
│   ├── detector.py            #   AttackDetector facade (wires the 3 rules below)
│   ├── anomaly_detector.py    #   Volume-based anomaly scoring
│   └── rules/
│       ├── brute_force.py
│       ├── sql_injection.py
│       └── xss.py
├── cli.py                     # `python cli.py --input <log> --analyze --visualize`
├── scripts/
│   └── visualize_results.py   # Matplotlib bar chart of detected attack types
├── backend/                   # Async ingestion service (independent of analyzer/)
│   ├── main.py                #   FastAPI app: /ingest, /health, /ping
│   ├── worker.py               #   Redis queue consumer, runs detection off the request path
│   ├── realtime/run.py        #   Streaming demo built on analyzer/
│   └── Dockerfile
├── data/sample_access.log     # Sample log with one of each attack type, for demos/tests
├── tests/                     # pytest suite (11 tests, one per detection path + regressions)
├── experiments/               # Benchmarking / prototype scratch space, not part of the shipped path
└── websitesite/               # Next.js landing page (not audited as part of the backend fix)
```

**Note:** `analyzer/` and `backend/main.py`/`backend/worker.py` are two
independent detection implementations (the backend originally shipped as a
separate service with its own inline regex detectors). They aren't wired
together — `backend/realtime/run.py` is the one backend component that uses
`analyzer/` directly. Consolidating them into a single detection engine is
a reasonable next step but is a larger refactor than a bug fix; see
[Known limitations](#known-limitations).

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

For the backend service specifically:

```bash
pip install -r backend/requirements.txt
```

## Usage

### CLI (one-shot analysis of a log file)

```bash
python cli.py --input data/sample_access.log --analyze --visualize
```

- `--analyze` runs all three detectors and prints a per-type count.
- `--visualize` renders a bar chart of detected attack types
  (`attack_trends.png` if no display is available, e.g. on a server/CI).

### Backend API (async ingestion via Redis)

```bash
export REDIS_URL=redis://localhost:6379/0   # omit to run in inline/no-queue mode
uvicorn backend.main:app --reload

# in another terminal, run the worker (consumes the queue):
cd backend && python worker.py
```

```bash
curl -X POST http://localhost:8000/ingest \
  -F "raw=$(cat data/sample_access.log)"
```

Without `REDIS_URL` set, `/ingest` analyzes inline and returns results
directly (fine for local testing, not recommended for production — see
[Known limitations](#known-limitations)). Brute-force sensitivity is
tunable via `BRUTEFORCE_THRESHOLD` (default `5`).

### Real-time streaming demo

```bash
python -m backend.realtime.run
```

Streams `data/sample_access.log` line-by-line (simulating `tail -f`),
running each line through the same `analyzer/` detection stack as the CLI,
with a simple per-IP risk score.

## Testing

```bash
pytest tests/ -v
```

11 tests, covering: log parsing (including malformed lines and payloads
with embedded spaces), brute force (on-threshold, below-threshold, and
non-`/login` endpoints), SQL injection (plain and percent-encoded), XSS
(plain and percent-encoded), and anomaly detection.

## Known limitations

Documented here deliberately, rather than left for someone to discover in
production:

- **Detection is regex/threshold-based, not ML.** It will not catch
  attacks split across multiple encoding layers, obfuscated payloads, or
  slow/low-and-slow brute force spread across many IPs (no distributed
  attack correlation).
- **`analyzer/` and `backend/main.py` are two separate detection
  implementations.** They currently agree on detection *logic* but are not
  the same code path — a fix to one does not automatically apply to the
  other. `backend/realtime/run.py` is the only backend entry point that
  uses `analyzer/` directly.
- **Anomaly detection is a single-batch heuristic**, not a time-series
  baseline — it compares IPs against each other within one call, not
  against historical norms for that IP.
- **No authentication on the `/ingest` endpoint.** Fine for local/demo use;
  put it behind an API gateway or add auth before exposing it externally.

## Contributing

See `CONTRIBUTING.md`.

## License

See `LICENSE`.
