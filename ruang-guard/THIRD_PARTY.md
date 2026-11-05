# Bundled browser dependency

Chart.js **4.6.1**, MIT license, is served locally at `/static/vendor/chart.umd.min.js`. No CDN or external request is required by the dashboard at runtime.

- Upstream: https://github.com/chartjs/Chart.js/releases/tag/v4.6.1
- Distribution: https://registry.npmjs.org/chart.js/-/chart.js-4.6.1.tgz (`package/dist/chart.umd.js`, already minified)
- Local file SHA-256: `fae96e55c6daa9ea7b3f60b6e6ea153904f510f6e00f59ed5ba3be21df231cd2`
- Chart.js license: `guard/static/vendor/chartjs-LICENSE.md`.
- The bundled color utility @kurkle/color 0.3.2 is part of Chart.js, not a separate chart library. Its MIT notice is retained in `guard/static/vendor/kurkle-color-LICENSE.md`.

The filename is changed to `chart.umd.min.js`. Upstream source-map linkage is omitted if present; no source map is shipped. When updating, verify the npm distribution integrity, retain licenses, recalculate this checksum, and rerun dashboard browser checks.


# ML worker dependencies

The separate ML worker uses scikit-learn **1.7.2** (BSD-3-Clause) and NumPy **2.2.6** (BSD-3-Clause), pinned in requirements-ml.txt. scipy, joblib and threadpoolctl are installed as scikit-learn dependencies; notices remain inside the installed distributions. This section is not a complete dependency inventory or SBOM. No serialized third-party model is bundled or downloaded.

- scikit-learn project/distribution: https://pypi.org/project/scikit-learn/1.7.2/
- scikit-learn license: https://github.com/scikit-learn/scikit-learn/blob/1.7.2/COPYING
- NumPy distribution: https://pypi.org/project/numpy/2.2.6/
- NumPy license: https://github.com/numpy/numpy/blob/v2.2.6/LICENSE.txt

Model fitting/inference runs only in the ML worker. No ML browser library, CDN, external inference API or hosted training service is used. Docker builds/pip installation require registry access; normal operation does not.
