<<<<<<< HEAD
# Contributing to LogSentinel

Thanks for considering a contribution — this is a small, focused project and
PRs of any size are welcome.

## Getting set up

```bash
git clone https://github.com/<you>/logsentinel.git
cd logsentinel/backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/ -v
```

If the tests pass, you're ready to go.

## Before opening a PR

- **Run the tests.** `python -m pytest tests/ -v` from `backend/`. New
  detection logic needs a test that would have failed without your change.
- **Run the CLI against the sample log** (`python cli.py --input
  ../data/sample_access.log`) as a sanity check — it's the fastest way to
  catch a broken import or syntax error before it reaches CI.
- Keep detectors in `app/detectors/` — one file per rule, each exposing an
  `analyze(entry)` method that returns `None` or an alert dict. `AttackDetector`
  in `app/detector.py` is the only place they get wired together.
- If you add a new detector, register it in `AttackDetector.__init__` and
  add both a positive and a negative (no-false-positive) test.

## Ideas for contributions

- Additional detection rules (command injection, SSRF probes, known bad
  user-agents / scanner fingerprints)
- Nginx log format support alongside Apache combined
- A "replay" mode that ingests a real log file at simulated real-time speed
- Rate-limiting / IP allowlisting for the `/api/ingest` path if you extend it
- Export alerts to CSV/JSON from the dashboard

## Reporting bugs

Open an issue with the log line (redact IPs if needed) or steps that
reproduce it, plus what you expected vs. what happened. A failing test is
even better than a description.

## Code style

Plain, readable Python — type hints on public functions, docstrings on
non-obvious modules. No linter is enforced yet; keeping it consistent with
the surrounding file is enough.
=======
# Contributing to Log Analyzer for Attack Detection

Thank you for considering contributing! This project is open for Hacktoberfest and welcomes improvements in parsing, rules, and visualization.

---

## 🪜 How to Contribute

1. **Fork the repository** to your GitHub account.
2. **Create a new branch** for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
>>>>>>> origin/main
