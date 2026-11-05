# Ruang Warga — fictional complaint portal

An independent Flask/SQLite application for testing security controls with fictional data. It is not a government service and has no external integration. Do not submit personal or real complaint information.

## Recommended: protected mode

Follow the repository [installation guide](../docs/INSTALLATION.md). Run the integrated Compose project from `../ruang-guard` and access **http://localhost:8090**. The portal's port 8000 remains private. Do not start the standalone Compose file at the same time.

## Application workflow

1. Create a complaint with a title of 8–120 characters, an available category, a location of 3–100 characters, and a description of 30–3000 characters.
2. Store the reference and random access key returned once on creation.
3. Retrieve status using both values. The database stores only the access-key hash; a reference alone is insufficient.
4. Search and download fictional TXT guidance documents from a fixed document allowlist.

New reports have status `Diterima`. There is no portal administrator workflow, attachment upload, or lost-key recovery. Home-page illustrative statistics are fixed fictional data, unlike the security dashboard's real event aggregates.

## API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Application/database health |
| GET | `/api/categories` | Available categories |
| GET | `/api/statistics` | Fixed illustrative statistics |
| POST | `/api/complaints` | Create a fictional complaint; returns 201, reference, access key |
| POST | `/api/complaints/status` | Retrieve with `reference` and `access_token` |
| GET | `/api/documents?q=privasi` | Search document titles/descriptions |
| GET | `/api/documents/panduan/download` | Download a fixed allowed document ID |

POST requests require JSON and `X-Lab-Request: 1`. Browser requests must satisfy the same-origin checks. Example through the gateway:

```powershell
$headers = @{ 'X-Lab-Request' = '1' }
$body = @{
  title = 'Lampu taman rekaan tidak menyala'
  category = 'Lingkungan'
  location = 'Taman Awan, Kota Imaji'
  description = 'Tiga lampu taman rekaan tidak menyala dalam simulasi. Mohon pemeriksaan fiktif.'
} | ConvertTo-Json
$receipt = Invoke-RestMethod http://localhost:8090/api/complaints -Method Post -Headers $headers -ContentType 'application/json' -Body $body
$lookup = @{reference=$receipt.reference; access_token=$receipt.access_token} | ConvertTo-Json
Invoke-RestMethod http://localhost:8090/api/complaints/status -Method Post -Headers $headers -ContentType 'application/json' -Body $lookup
```

Do not publish the receipt/access key. API errors distinguish validation, content type, access failure, body limits, and rate limits; 429 includes `Retry-After`.

## Standalone development only

From this directory, `docker compose up -d --build` serves the **unprotected standalone portal** at http://localhost:8000. Stop that standalone instance with `docker compose down` before switching to the integrated gateway lab. Standalone and integrated Compose use separate data volumes; data is not migrated automatically.

For native Python development, install `requirements.txt` into a virtual environment and run `waitress-serve --listen=127.0.0.1:8000 --call app:create_app`. Tests use temporary databases:

```sh
python -m unittest discover -s tests -p 'test_*.py' -v
```

The application keeps parameterized SQL, input size/type checks, random report access keys, safe text rendering, and Host/Origin validation even when a WAF is present. No intentional vulnerabilities are included. See [security boundaries](../SECURITY.md).
