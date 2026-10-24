# Contributing

Open an issue with a minimal synthetic input and expected behavior. Please keep private data out of reports.

Use Python 3.11+ and an isolated environment:

```sh
python -m venv .venv
# POSIX: .venv/bin/python; Windows: .venv\Scripts\python.exe
python -m pip install -e . build ruff==0.17.2
python -m unittest discover -s tests -v
python -m ruff check .
python -m ruff format --check .
python -m build
```

Activate the environment or use its Python path explicitly before these commands.
Changes should include a regression test when they affect behavior. Keep the runtime dependency free.
There are no bot commit workflows or automatic dependency update merges. Third-party contributions
are reviewed as issues; the maintainer does not automatically merge external pull requests.
