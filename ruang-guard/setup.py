"""Generate local secrets without printing them or overwriting existing credentials."""
from pathlib import Path
import secrets
from werkzeug.security import generate_password_hash

root = Path(__file__).resolve().parent
folder = root / 'secrets'
folder.mkdir(mode=0o700, exist_ok=True)
paths = [folder / name for name in ('session_key','admin_hash','initial-password.txt')]
if any(path.exists() for path in paths):
    raise SystemExit('Secrets already exist. No files overwritten.')
password = secrets.token_urlsafe(24)
for path, value in zip(paths, [secrets.token_urlsafe(48), generate_password_hash(password, method='scrypt'), password]):
    with path.open('x', encoding='utf-8') as out:
        out.write(value + '\n')
    # File-backed Compose secrets keep host permissions. A private parent directory
    # protects host access; mounted hash/key must be readable by the non-root UID.
    path.chmod(0o600 if path.name == 'initial-password.txt' else 0o444)
print('Secrets generated. Read secrets/initial-password.txt locally to sign in. Do not commit or share these files.')
