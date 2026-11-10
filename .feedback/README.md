# Feedback task starting environment

Upstream: https://github.com/python-hyper/wsproto
Upstream commit: `5e0685d0740ec30716897442f336de1118f5f40a`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-10): `230 passed in 0.75s`
Whole-command wall time: 1.088 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
