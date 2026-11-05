"""Shared state, allowlisted origins, and privacy-preserving event storage."""
from contextlib import contextmanager
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time

import requests


class Store:
    def __init__(self, path, secret, origins, now=time.time):
        self.path, self.secret, self.now = str(path), secret, now
        self.origins = validate_origins(origins)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), origin TEXT, rate INTEGER, window INTEGER, duration INTEGER);
            CREATE TABLE IF NOT EXISTS counters (client TEXT PRIMARY KEY, start REAL, count INTEGER);
            CREATE TABLE IF NOT EXISTS offenses(client TEXT PRIMARY KEY,level INTEGER,last REAL,duration INTEGER);
            CREATE TABLE IF NOT EXISTS blocks (client TEXT PRIMARY KEY, expires REAL, reason TEXT);
            CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, csrf TEXT, authenticated INTEGER, expires REAL);
            CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, at REAL, client TEXT, method TEXT, route TEXT, status INTEGER, decision TEXT, reason TEXT, rules TEXT, ms REAL);
            CREATE TABLE IF NOT EXISTS health (id INTEGER PRIMARY KEY, at REAL, origin TEXT, available INTEGER, status INTEGER, ms REAL);
            CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at REAL, action TEXT, target TEXT);
            ''')
            db.execute('INSERT OR IGNORE INTO settings VALUES(1,?,120,60,72)', (next(iter(self.origins)),))
            # Old events remain unassigned; never guess their historical origin.
            if 'origin' not in {r['name'] for r in db.execute('PRAGMA table_info(events)')}:
                db.execute('ALTER TABLE events ADD COLUMN origin TEXT')
        if self.settings()['origin'] not in self.origins:
            raise ValueError('Selected origin is no longer allowlisted; restore configuration before starting.')

    @contextmanager
    def db(self, write=False):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                if write:
                    db.execute('BEGIN IMMEDIATE')
                yield db
        finally:
            db.close()

    def identity(self, address):
        return hmac.new(self.secret.encode(), address.encode(), hashlib.sha256).hexdigest()[:24]

    def settings(self):
        with self.db() as db:
            return dict(db.execute('SELECT * FROM settings WHERE id=1').fetchone())

    def update(self, origin, rate, window, duration):
        if origin not in self.origins or not (1 <= rate <= 10000 and 1 <= window <= 3600 and 1 <= duration <= 3600):
            raise ValueError('Konfigurasi di luar batas atau origin tidak diizinkan.')
        with self.db(True) as db:
            db.execute('UPDATE settings SET origin=?,rate=?,window=?,duration=? WHERE id=1', (origin, rate, window, duration))
            db.execute('DELETE FROM counters')
            db.execute('INSERT INTO audit(at,action,target) VALUES(?,?,?)', (self.now(), 'update_settings', origin))

    def limit(self, client, *, login=False):
        now = self.now()
        config = dict(rate=5, window=60, duration=300) if login else self.settings()
        key = ('login:' if login else '') + client
        with self.db(True) as db:
            row = db.execute('SELECT * FROM blocks WHERE client=?', (key,)).fetchone()
            if row and row['expires'] > now:
                return max(1, int(row['expires'] - now + 0.999)), row['reason']
            if row:
                db.execute('DELETE FROM blocks WHERE client=?', (key,))
                db.execute('DELETE FROM counters WHERE client=?', (key,))
            row = db.execute('SELECT * FROM counters WHERE client=?', (key,)).fetchone()
            if row is None or now >= row['start'] + config['window']:
                db.execute('INSERT OR REPLACE INTO counters VALUES(?,?,1)', (key, now))
                return 0, ''
            if row['count'] >= config['rate']:
                duration = self._penalty(db,key,config['duration'],now)
                db.execute('INSERT OR REPLACE INTO blocks VALUES(?,?,?)', (key, now + duration, 'login_limit' if login else 'rate_limit'))
                return duration, 'login_limit' if login else 'rate_limit'
            db.execute('UPDATE counters SET count=count+1 WHERE client=?', (key,))
        return 0, ''

    def _penalty(self, db, client, base, now):
        previous=db.execute('SELECT * FROM offenses WHERE client=?',(client,)).fetchone()
        level=min(previous['level']+1,32) if previous and now-previous['last']<86400 else 1
        duration=min(3600,base*(2**min(level-1,16)))
        db.execute('INSERT OR REPLACE INTO offenses VALUES(?,?,?,?)',(client,level,now,duration))
        return duration

    def block(self, client, reason):
        now=self.now()
        base=self.settings()['duration']
        with self.db(True) as db:
            active=db.execute('SELECT expires FROM blocks WHERE client=? AND expires>?',(client,now)).fetchone()
            if active:return max(1,int(active['expires']-now+.999))
            duration=self._penalty(db,client,base,now)
            db.execute('INSERT OR REPLACE INTO blocks VALUES(?,?,?)',(client,now+duration,reason))
            return duration

    def unblock(self, client):
        with self.db(True) as db:
            db.execute('DELETE FROM blocks WHERE client=?', (client,))
            db.execute('DELETE FROM counters WHERE client=?', (client,))
            db.execute('DELETE FROM offenses WHERE client=?', (client,))
            db.execute('INSERT INTO audit(at,action,target) VALUES(?,?,?)', (self.now(), 'unblock', client))

    def event(self, client, method, route, status, decision, reason, rules, ms, origin=None):
        # Only explicitly safe metadata enters persistence; never headers, URI query, body, or errors.
        safe_method = method if method in {'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'} else 'OTHER'
        with self.db() as db:
            db.execute('INSERT INTO events(at,client,method,route,status,decision,reason,rules,ms,origin) VALUES(?,?,?,?,?,?,?,?,?,?)',
                       (self.now(), client, safe_method, route_label(route), status, decision, reason, json.dumps(rules), round(ms, 2), origin if origin in self.origins else None))

    def snapshot(self):
        with self.db() as db:
            events = [dict(r) for r in db.execute('SELECT * FROM events ORDER BY id DESC LIMIT 100')]
            for event in events:
                event['rules'] = json.loads(event['rules'])
            return dict(settings=self.settings(), origins=list(self.origins), events=events,
                        totals=dict(db.execute("SELECT COUNT(*) AS total, COALESCE(SUM(decision='allowed'),0) AS allowed, COALESCE(SUM(decision='blocked'),0) AS blocked, COALESCE(SUM(decision='error'),0) AS errors FROM events").fetchone()),
                        blocks=[dict(r) for r in db.execute('SELECT b.*,CASE WHEN b.reason=? THEN 0 ELSE COALESCE(o.level,0) END AS level,o.duration FROM blocks b LEFT JOIN offenses o ON o.client=b.client WHERE b.expires>? ORDER BY b.expires DESC', ('ml_review',self.now()))],
                        offenses=[dict(r) for r in db.execute('SELECT * FROM offenses WHERE last>? ORDER BY last DESC LIMIT 100',(self.now()-86400,))],
                        health=[dict(r) for r in db.execute('SELECT * FROM health WHERE origin=? ORDER BY id DESC LIMIT 30', (self.settings()['origin'],))],
                        audit=[dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 20')])

    def cleanup(self):
        now = self.now()
        with self.db(True) as db:
            for table in ('events', 'health', 'audit'):
                db.execute(f'DELETE FROM {table} WHERE at < ? OR id NOT IN (SELECT id FROM {table} ORDER BY id DESC LIMIT 10000)', (now - 7 * 86400,))
            db.execute('DELETE FROM sessions WHERE expires < ?', (now,))
            # Expiry must reset the same counter as limit(), even if cleanup runs
            # before the next request. Both deletes share the write transaction.
            db.execute('DELETE FROM counters WHERE client IN (SELECT client FROM blocks WHERE expires <= ?)', (now,))
            db.execute('DELETE FROM blocks WHERE expires <= ?', (now,))
            db.execute('DELETE FROM counters WHERE start < ?', (now - 86400,))
            db.execute('DELETE FROM offenses WHERE last<=?',(now-86400,))


def route_label(path):
    known = {'/', '/pengaduan', '/status', '/dokumen', '/api/health', '/api/categories', '/api/statistics', '/api/complaints', '/api/complaints/status', '/api/documents'}
    if path in known:
        return path
    if path.startswith('/static/'):
        return '/static/*'
    if path.startswith('/api/documents/'):
        return '/api/documents/*'
    return '[other]'


def validate_origins(origins):
    if not isinstance(origins, dict) or not origins:
        raise ValueError('An explicit origin allowlist is required.')
    for key, value in origins.items():
        if not key or len(key) > 50 or not all(c.isalnum() or c in '-_' for c in key):
            raise ValueError('Invalid origin ID')
        if set(value) != {'address', 'port', 'health_path'}:
            raise ValueError('Origins require literal address, port, health_path only.')
        ip = ipaddress.ip_address(value['address'])
        # This edition deliberately supports only RFC1918 IPv4 lab destinations.
        if ip.version != 4 or not any(ip in ipaddress.ip_network(net) for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
            raise ValueError('Only explicit RFC1918 lab addresses are allowed; no DNS, metadata, loopback or public targets.')
        if type(value['port']) is not int or not 1 <= value['port'] <= 65535:
            raise ValueError('Invalid port')
        if value['health_path'] not in {'/api/health', '/health', '/healthz', '/'}:
            raise ValueError('Unsupported health path')
    return origins


def load_store():
    secret = Path(os.getenv('SECRET_FILE', '/run/secrets/session_key')).read_text().strip()
    if len(secret) < 32:
        raise ValueError('Secret must contain at least 32 random characters.')
    origins = json.loads(Path(os.getenv('ORIGINS_FILE', '/app/config/origins.json')).read_text())
    return Store(os.getenv('DATABASE', '/data/guard.db'), secret, origins)


def origin_url(origin):
    return f"http://{origin['address']}:{origin['port']}"


def http_session():
    session = requests.Session()
    session.trust_env = False  # No system proxy or .netrc credentials.
    return session


def check_health(store, public_host='localhost:8090', session_factory=http_session):
    selected = store.settings()['origin']
    origin = store.origins[selected]
    start = time.monotonic()
    status = 0
    try:
        with session_factory() as client:
            with client.get(origin_url(origin) + origin['health_path'], headers={'Host': public_host}, timeout=(2, 3), allow_redirects=False, stream=True) as response:
                status = response.status_code
    except requests.RequestException:
        pass
    with store.db() as db:
        db.execute('INSERT INTO health(at,origin,available,status,ms) VALUES(?,?,?,?,?)', (store.now(), selected, int(200 <= status < 300), status, round((time.monotonic() - start)*1000, 2)))
