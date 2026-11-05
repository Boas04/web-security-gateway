# Testing and evaluation

[Back to README](../README.md)

Use only the fictional local lab. Commands below run from `ruang-guard/` unless noted. Do not interpret a few blocked payloads as complete attack coverage or DDoS capacity.

## 1. Python unit and in-process integration tests

Install the ML dependencies into the local virtual environment as well as the base requirements:

```powershell
.\.venv\Scripts\python -m pip install -r requirements-ml.txt
.\.venv\Scripts\python -m unittest discover -s tests -p "test_*.py" -v
```

On Linux/macOS, use `.venv/bin/python`. These tests use temporary databases. Most WAF policy tests inject an inspector verdict; real-inspector tests skip unless `WAF_TEST_URL` is set. Read the skipped-test count instead of claiming that this command alone exercises Coraza.

Test the standalone portal from `ruang-warga/` using the same environment:

```powershell
..\ruang-guard\.venv\Scripts\python -m unittest discover -s tests -p "test_*.py" -v
```

Linux/macOS equivalent: `../ruang-guard/.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v`.

## 2. Real WAF tests

The WAF Dockerfile runs `go test ./...` while building. With Docker available:

```sh
docker compose -p ruang-guard build waf
```

Then run the Python suite against a dedicated inspector:

```powershell
.\.venv\Scripts\python tests/run_all.py
```

This starts a temporary WAF container on **127.0.0.1:18081**, refuses to replace an existing test container, and stops its own container afterward. It requires the image built under project name `ruang-guard`. The source applications are exercised in-process; this does not by itself verify every Compose network boundary. Results go to ignored `test-results/unit-verification.json`.

For native Go development, run `go test ./...` in `waf/` with a toolchain compatible with its module dependencies; the Dockerfile pins the build toolchain used by the lab.

## 3. Full local Docker acceptance

Start the integrated stack first and keep `secrets/initial-password.txt` available locally. Run these sequentially in a disposable lab session:

```powershell
.\.venv\Scripts\python tests/final_acceptance.py
.\.venv\Scripts\python tests/integration_features.py
```

`final_acceptance.py` includes the base integration suite; running `integration.py` separately is optional. The checks cover normal complaint creation and private status retrieval, real CRS rule families for SQLi/XSS/path traversal, rate limits, progressive expiry, administrator authentication/CSRF, technical failures, and no published origin port. Brute-force checks target the lab administrator login; they do not prove protection for every customer authentication flow.

The tests intentionally stop/restart this lab's origin and WAF, alter/restore policy, clear temporary blocks, and create fictional data. The feature suite starts/stops the optional demo as needed. Cleanup runs on normal completion or exceptions; forced process termination can leave state requiring manual recovery. Do not run them during another demonstration or against an unrelated service occupying these ports. Final acceptance writes `test-results/final-security.json`.

## 4. Offline ML evaluation

```powershell
.\.venv\Scripts\python tests/evaluate_ml.py test-results/ml-evaluation.json
```

This trains and evaluates a real Isolation Forest using a small, intentionally simple synthetic fixture and a temporary database. It does not contact the running lab. Reported precision/recall are **fixture results, not production accuracy or SQLi/XSS classification performance**.

## 5. Controlled live ML lifecycle

```powershell
.\.venv\Scripts\python tests/live_ml.py
```

This optional test takes about nine minutes. Six temporary local clients generate normal fictional traffic over seven one-minute periods. Their eligible windows are approved as the lab baseline; the candidate is trained, validated, and activated through the administrator API. A bounded unknown-route pattern is then reviewed, temporarily blocked by the administrator, and unblocked.

It writes `test-results/live-ml-verification.json`. It restores the gateway settings and removes its helper containers, **but deliberately leaves the generated traffic, baseline, and activated model in the lab**. Use a disposable installation if the current ML state must be preserved.

## 6. Optional bounded traffic evaluation

```powershell
.\.venv\Scripts\python tests/evaluate_local.py
```

The evaluator targets only the local gateway, checks the fictional portal identity, and uses a bounded number of requests. It waits for blocks to expire rather than altering policy. Reports are written to ignored sibling `ruang-guard-evaluation-<timestamp>/` directories. It is not a volumetric DDoS simulator or a maximum-capacity benchmark. Public status codes alone do not prove which CRS rule fired; confirm rule IDs in the authenticated dashboard or acceptance tests.

## Record evidence honestly

Record the commit, environment, configuration, commands, failures/skips, and artifact timestamps. Separate unit checks, real-inspector checks, Docker end-to-end evidence, and ML fixture metrics. See [publication verification](VERIFICATION.md) for what was actually rerun for this repository.
