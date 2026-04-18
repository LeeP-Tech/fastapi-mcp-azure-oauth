# Contributing

Thank you for considering a contribution to **fastapi-mcp-azure-oauth**! This document explains the process from idea to merged pull request.

---

## Table of contents

- [Code of Conduct](#code-of-conduct)
- [Reporting bugs](#reporting-bugs)
- [Requesting features](#requesting-features)
- [Development setup](#development-setup)
- [Running the tests](#running-the-tests)
- [Coding standards](#coding-standards)
- [Submitting a pull request](#submitting-a-pull-request)
- [Releasing](#releasing)

---

## Code of Conduct

This project adopts the [Contributor Covenant](https://www.contributor-covenant.org/) Code of Conduct. Be respectful and constructive.

---

## Reporting bugs

1. Search [existing issues](https://github.com/LeeP-Tech/fastapi-mcp-azure-oauth/issues) first.
2. If not found, open a new issue with:
   - A clear title
   - Steps to reproduce
   - Expected vs. actual behaviour
   - Python and FastAPI versions
   - Relevant exception traceback or log output

For **security** vulnerabilities, see [SECURITY.md](SECURITY.md) — do **not** open a public issue.

---

## Requesting features

Open an issue tagged `enhancement`. Describe the use case and the proposed API. The more concrete the example, the faster the discussion moves.

---

## Development setup

```bash
git clone https://github.com/LeeP-Tech/fastapi-mcp-azure-oauth.git
cd fastapi-mcp-azure-oauth

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

---

## Running the tests

```bash
# All tests
pytest

# With coverage
pytest --cov --cov-report=term-missing

# A single file
pytest tests/test_validator.py -v
```

The CI gate requires **100% coverage** on all source modules. Every new code path must be accompanied by a test.

---

## Coding standards

- **Python 3.10+** — use `|` union syntax, `match` where appropriate.
- **Type annotations** on all public functions and methods.
- **No external runtime dependencies** beyond `fastapi`, `httpx`, `PyJWT[crypto]`, and `pydantic`.
- Docstrings on all public symbols — Google style.
- Keep lines under 100 characters.
- Run `python -m py_compile src/**/*.py` before submitting to catch syntax errors.

There is intentionally **no linter config** in this repository — contributors should use the tool of their choice. The only hard requirement is that the test suite passes at 100% coverage.

---

## Submitting a pull request

1. Fork the repository and create a branch: `git checkout -b fix/my-fix` or `feat/my-feature`.
2. Make your changes, add tests.
3. Ensure `pytest --cov` reports 100% coverage on all `src/` files.
4. Update `CHANGELOG.md` under `[Unreleased]`.
5. Open a pull request against `main`. Fill in the PR template.

Pull requests are squash-merged. The commit message becomes the changelog entry, so write it clearly.

---

## Releasing

Releases are managed by the maintainers:

1. Update `CHANGELOG.md` — move `[Unreleased]` to a versioned section.
2. Bump `version` in `pyproject.toml` and `src/fastapi_mcp_azure_oauth/__init__.py`.
3. Commit: `git commit -m "Release v1.x.y"`.
4. Tag: `git tag v1.x.y && git push --tags`.
5. The CI `publish` job picks up the tag and publishes to PyPI automatically.
