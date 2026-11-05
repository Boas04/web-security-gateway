# Publication verification

[Back to README](../README.md)

Checked on **5 November 2026** against the clean publication checkout. These results describe the commands actually completed for this publication; they do not substitute for a fresh end-to-end deployment on another machine.

## Completed checks

| Check | Result | Scope |
| --- | --- | --- |
| Gateway Python discovery | 71 discovered: 66 passed, 5 initially skipped | Temporary databases, policy/authentication/CSRF, expiry/escalation, metadata, alerts, statistics, ML lifecycle and coordination. |
| Real Coraza integration | All 5 initially skipped tests subsequently passed | Dedicated native inspector on 127.0.0.1:18081; SQLi, XSS, traversal, redacted verdicts, and a normal complaint/access-key round trip. Origin transport was in-process. |
| Portal Python suite | 7 passed | Standalone application validation, access control, persistence, document routes, and rate limiting. |
| Native Go tests | TestCRS and all 9 subtests passed, cache disabled | Actual Coraza/CRS, including malformed input, normal requests, SQLi/XSS/traversal, JSON inspection, and size limits. |
| Offline ML evaluator | Completed | Small synthetic fixture: TP 10, FP 2, TN 28, FN 0; zero automatic blocks. Not production accuracy. |
| Compose configuration | Passed, default and demo profiles | Configuration validation, not runtime connectivity. |
| WAF Docker build | Succeeded | Build reused cached Go-test/build layers; native Go tests above were separately rerun without test cache. |
| Python syntax and dashboard JavaScript syntax | Passed | Compilation/parse checks; no fresh visual browser audit claimed. |

Native Python environment: Python 3.10.6, Flask 3.1.3, scikit-learn 1.7.2, NumPy 2.2.6, requests 2.32.5. The repository pins requests 2.33.1 for installation; native tests therefore do **not** constitute a clean-install test of that exact dependency set. Containers use their Dockerfile-defined runtimes.

## Not rerun for this publication

- Complete Docker acceptance with origin/WAF outages and network bypass checks.
- The approximately nine-minute live ML training/activation demonstration.
- A fresh full-stack image build from an empty cache.
- Visual browser checks, load capacity measurement, or production deployment tests.

Docker was available for the WAF build but its daemon became unavailable before the additional container-based inspector run. The real-inspector tests were completed using a locally built native inspector instead. No successful Docker end-to-end result is claimed for this publication.

Follow [TESTING.md](TESTING.md) to repeat the full lab checks. Generated local evidence is written to ignored test-results directories; private development reports, databases, credentials, academic documents, and unrelated Docker restoration information are not distributed.

## Publication-specific changes

- Added a professional English README, an Indonesian guide, and installation, usage, architecture, security, and testing documentation.
- Kept the independent gateway and portal folders adjacent so the existing Compose build relationship remains valid.
- Updated three test-report destinations to a locally created, ignored `ruang-guard/test-results/` directory; made the offline evaluator create its output parent directory.
- Corrected stale documentation about the service count and report paths.
- Added repository-level ignore rules and consistent text line endings. Runtime gateway/WAF/ML policy code was not changed for publication.
