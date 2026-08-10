<<<<<<< HEAD
# Research notes

Notes on the design decisions behind this project, kept here rather than in
the README to keep that focused on usage.

## What prompted this project

This project started as a review of a similar public repo (a Python Apache
log analyzer with the same three detection categories: brute force, SQLi,
XSS). That review, done by actually cloning and running the code rather than
trusting its README, found:

- `analyzer/parser.py` contained a corrupted docstring (escaped quote
  characters where literal `"""` should have been), producing a hard
  `SyntaxError`. Since every entry point — the CLI, the FastAPI backend, and
  the test suite — imported from that module, **the entire project failed to
  run**: not one of its three documented ways to use it (CLI, API, streaming
  demo) could actually execute.
- Its README's "Known Limitations" section (no auth on `/ingest`, two
  divergent detection implementations) turned out to describe an *earlier*
  version of the backend that had since been partially fixed in the actual
  code — the docs just hadn't been updated to match, so the README couldn't
  be trusted as an accurate snapshot either.
- The anomaly detector compared IPs only against each other within a single
  batch, with no persistence — a same-call heuristic rather than a real
  baseline.

None of that is a knock on the idea — signature-based log analysis is a
legitimately useful, approachable project. It's why this version exists:
same core idea, built and verified to actually run end-to-end, with a real
historical baseline for anomaly detection and one detection engine instead
of two.

## Design decisions

- **SQLite over Postgres/Redis.** The predecessor's backend required Redis
  for its async ingestion path. For a project explicitly meant to run
  locally with nothing to host, an embedded file-based database removes an
  entire service dependency without losing the ability to persist alert
  history and traffic baselines across requests.
- **Vanilla JS dashboard over a React/Vite frontend.** A build step is one
  more thing that can silently break between "wrote it" and "someone else
  clones it and runs it." Serving plain HTML/CSS/JS as static files from the
  same FastAPI process removes an entire class of failure (Node version
  mismatches, `npm install` failures, stale build artifacts) at minimal cost
  to functionality for a dashboard this size.
- **A traffic simulator instead of requiring real logs.** Most people
  evaluating a security tool don't have a spare Apache access log with real
  attacks in it lying around. Generating realistic synthetic traffic through
  the *same* detection pipeline used everywhere else means the dashboard has
  something genuine to show on first run, not a canned demo recording.
- **Path traversal as a fourth detector.** Not in the predecessor's scope;
  added because it's one of the most common opportunistic scans in real
  Apache logs (`/etc/passwd`, `boot.ini` probes) and the marginal
  implementation cost was small given the existing percent-decode-then-match
  pattern from the SQLi/XSS detectors.
=======
# R&D Core Research

This document defines the baseline objectives of the R&D initiative:
- Establish an experimental environment for algorithmic exploration.
- Document findings and performance benchmarks.
- Maintain reproducibility across research phases.
>>>>>>> origin/main
