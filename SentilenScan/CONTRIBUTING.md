# Contributing to SentinelScan

Thanks for considering a contribution. This project welcomes bug reports,
new analyzers, documentation fixes, and packaging work.

## Ground rules

- By participating, you're expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Found a security vulnerability *in SentinelScan itself*? Don't open a public
  issue — see [SECURITY.md](SECURITY.md) for responsible disclosure.
- SentinelScan actively probes the targets it scans. Never test changes
  against a target you don't own or have explicit authorization to test —
  `example.com` and your own infrastructure are the go-to choices during
  development.

## Development setup

```bash
git clone https://github.com/aljabid/SentinelScan.git
cd sentinelscan
pip install -e ".[dev,dns]"
```

This installs the package in editable mode plus `pytest`, `ruff`, `black`,
`mypy`, and `dnspython`.

## Before opening a PR

Run the full local check — this is exactly what CI runs, so passing it
locally means CI will pass too:

```bash
pytest tests/ -v
ruff check sentinelscan/ tests/
black --check sentinelscan/ tests/
mypy sentinelscan/
```

If `black` reports formatting issues, run `black sentinelscan/ tests/` to
fix them automatically before committing.

## Code style

- Default to **no comments**. Only add one when the *why* is genuinely
  non-obvious (a workaround, a hidden constraint) — not to restate what
  well-named code already says.
- Type hints are required on new code; the codebase is `mypy`-clean and CI
  enforces it.
- Match the existing analyzer/reporter patterns (see below) rather than
  introducing a new structure for a single check.
- Every new finding-producing code path needs a test. Mock `session`/`response`
  the way existing tests do (`unittest.mock.MagicMock`) — no real network
  calls in the test suite.

## Adding a check

Two paths, depending on scope:

1. **Built-in analyzer** (if it's broadly useful and you want it upstreamed):
   create `sentinelscan/analyzers/mycheck.py` inheriting `BaseAnalyzer`,
   register it in `scanner.py`'s `MODULE_MAP` and `cli.py`'s `ALL_MODULES`.
2. **Plugin** (if it's niche, internal, or you just want to try it locally):
   drop a `.py` file exposing an `ANALYZER` attribute into a plugin
   directory — no source changes needed.

Both are documented in detail in [CONFIG.md](CONFIG.md), including the full
interface (`self.response`, `self.session`, `self.add_finding()`, etc.).

## Adding a reporter

Reporters are plain classes with `__init__(self, severity_filter=None,
no_color=False)` and `render(self, all_results) -> str`. See
`sentinelscan/reporters/json_reporter.py` for the simplest example, or
`sarif_reporter.py` for a more structured one. Register the new class in
`cli.py`'s `REPORTERS` dict and add it to the `-f/--format` choices.

## Commit / PR conventions

- Keep PRs focused — one logical change per PR is much easier to review
  than a bundle of unrelated fixes.
- Write commit messages that explain *why*, not just *what* (the diff
  already shows what changed).
- Update `CHANGELOG.md` under `[Unreleased]` for any user-visible change.
- If you're adding a CLI flag, update `USAGE.md`/`CONFIG.md` and the man
  page (`man/sentinelscan.1`) in the same PR — undocumented flags are a
  recurring source of confusion.

## Reporting bugs / requesting features

Use the issue templates — they ask for the information needed to act on a
report quickly (version, target module, reproduction steps for bugs;
motivating use case for features).

## Where the roadmap lives

Until the project has a public GitHub Projects board set up, the roadmap is
tracked in `ENHANCEMENT_ANALYSIS.md`. If you want to work on something listed
there, open an issue first to avoid duplicate effort.
