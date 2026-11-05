# Installation

[Back to README](../README.md)

## Requirements

- Docker Engine/Desktop using Linux containers, with Compose v2.
- Python 3.10+ and pip for generating local credentials. Containers use Python 3.12.
- Git and internet access for the initial image/package downloads.
- Available loopback ports 8090 and 9000; the private subnet 172.30.10.0/24 must not conflict with existing Docker networks.

There are six default services, each with a memory limit: five at 256 MiB and the ML worker at 512 MiB. These limits sum to 1.75 GiB, **not a measured minimum host requirement**. Docker, the operating system, concurrent builds, and other applications need additional memory. The optional catalog adds 256 MiB. Review Docker resource availability before building.

## Fresh installation

Clone the complete repository and enter the security application:

```sh
git clone https://github.com/Boas04/web-security-gateway.git
cd web-security-gateway/ruang-guard
```

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python setup.py
Copy-Item .env.example .env
```

### Linux/macOS

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python setup.py
cp .env.example .env
```

`setup.py` generates a random session key, a scrypt administrator password hash, and an initial password file. It refuses to overwrite existing credentials. The generated files are excluded from Git. Restrict the secrets directory to your operating-system account; POSIX file modes do not substitute for Windows ACLs.

On either platform:

```sh
docker compose -p ruang-guard config --quiet
docker compose -p ruang-guard up -d --build
docker compose -p ruang-guard ps
```

The first build downloads dependencies and runs the Go WAF tests. `up -d` starts services but does not prove the complete system is ready. Check the actual health endpoint:

```powershell
# Windows
curl.exe -i http://localhost:8090/api/health
```

```sh
# Linux/macOS
curl -i http://localhost:8090/api/health
```

Expect HTTP 200 and `{"environment":"fictional-local-lab","status":"ok"}`. Wait briefly after startup if dependencies are still starting, then inspect logs if failures persist.

Open http://localhost:9000/admin/ and use the password in `secrets/initial-password.txt`. There is no fixed default password. The local browser dashboard is in Indonesian. Store the password privately; the automated live integration tests also use this file, so retain it only while running the lab tests that need it.

## Existing installations

Preserve `.env`, `secrets/`, and named data volumes. Do not rerun `setup.py` or replace the session key during ordinary updates. The key determines source pseudonyms, so changing it also changes their association with existing blocks.

After reviewing and pulling repository changes, run:

```sh
docker compose -p ruang-guard config --quiet
docker compose -p ruang-guard up -d --build
```

Do not start this checkout concurrently with another deployment named `ruang-guard`. Both would target the same Compose project and ports. Stop and identify the existing project first; do not stop unrelated containers to resolve a conflict.

## Stop and resume

```sh
docker compose -p ruang-guard stop
docker compose -p ruang-guard start
```

To remove this project's containers and networks while preserving named data volumes:

```sh
docker compose -p ruang-guard down
```

Use `up -d` to recreate them. Do not use volume deletion or global Docker pruning as a routine shutdown step.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Cannot connect to Docker | Start Docker Desktop/Engine, select Linux containers, and verify account permissions. |
| Port already allocated | Inspect `docker ps` and local listeners. Do not stop unrelated projects or change binding to 0.0.0.0. |
| Invalid PUBLIC_ORIGIN | Keep `.env` at `http://localhost:8090` (or supported alias `http://127.0.0.1:8090`). Shell environment variables can override `.env`. |
| HTTP 429 | Inspect `Retry-After` and the dashboard blocklist. Wait for expiry or explicitly unblock/reset the source. |
| HTTP 502 | Inspect origin availability and the selected origin ID. |
| HTTP 503 | Inspect the WAF service. Fail-closed behavior intentionally prevents forwarding. |
| Empty charts | Send a normal health request and choose a matching time range; statistics are not seeded. |
| No active ML model | Collect and approve a baseline, then train, validate, and activate a candidate. |
| Build cannot resolve registry/package | Restore registry/network access; image builds require internet even though normal operation is local. |

```sh
docker compose -p ruang-guard logs --tail 100 gateway waf admin monitor ml-worker portal
```

Do not share `.env`, the secrets directory, databases, or unreviewed local logs in support issues.
