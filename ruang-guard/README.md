# Security gateway application

This directory contains the reverse proxy, Coraza inspector, dashboard, health monitor, and ML worker. Its integrated Compose file builds the independent portal from the adjacent `../ruang-warga` directory.

Start with the repository [README](../README.md), [installation guide](../docs/INSTALLATION.md), or [Panduan Bahasa Indonesia](../docs/PANDUAN_ID.md). Run Compose commands from this directory with project name `ruang-guard`.

- [Dashboard, configuration, logs, and exports](../docs/USAGE.md)
- [Topology and security decisions](../docs/ARCHITECTURE.md)
- [Tests and evaluation](../docs/TESTING.md)
- [Publication verification](../docs/VERIFICATION.md)
- [ML lifecycle](ML_GUIDE.md)
- [WAF/ML coordination](COORDINATION_GUIDE.md)
- [Third-party components](THIRD_PARTY.md)

Gateway: http://localhost:8090. Dashboard: http://localhost:9000/admin/. Origin port 8000 remains internal. No generated credentials, production data, or pretrained model are distributed.
