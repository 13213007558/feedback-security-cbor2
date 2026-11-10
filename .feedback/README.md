# Feedback task starting environment

Upstream: https://github.com/agronholm/cbor2
Upstream commit: `93c598838d50b554e242920902aada82d32d55bc`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC CBOR2_BUILD_C_EXTENSION=0
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_decoder.py tests/test_encoder.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-10): `351 passed, 351 skipped in 1.85s`
Whole-command wall time: 2.216 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
