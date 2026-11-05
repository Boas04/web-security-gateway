"""Local-only fictional complaint portal. No external service integrations."""
import hashlib
from contextlib import contextmanager
import os
import secrets
import sqlite3
import time
from pathlib import Path
from flask import Flask, jsonify, render_template, request, Response
from werkzeug.exceptions import HTTPException

ROOT = Path(__file__).resolve().parent
CATEGORIES = ['Akses fasilitas', 'Layanan komunitas', 'Lingkungan', 'Lainnya']
DOCUMENTS = [
    {'id': 'panduan', 'title': 'Panduan pengaduan simulasi', 'description': 'Alur membuat laporan dan menyimpan kode pelacakan.'},
    {'id': 'privasi', 'title': 'Privasi dalam laboratorium', 'description': 'Gunakan identitas, lokasi, dan kejadian yang sepenuhnya fiktif.'},
    {'id': 'alur', 'title': 'Tahapan penanganan', 'description': 'Kenali status diterima, ditinjau, dan selesai.'},
]

def create_app(config=None):
    app = Flask(__name__)
    app.config.update(DATABASE=os.getenv('DATABASE', str(ROOT / 'data' / 'portal.db')),
                      MAX_CONTENT_LENGTH=16 * 1024, TRUSTED_HOSTS=['localhost', '127.0.0.1', '[::1]'],
                      RATE_LIMIT=int(os.getenv('RATE_LIMIT', '120')), RATE_WINDOW=60)
    if config:
        app.config.update(config)
    Path(app.config['DATABASE']).parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def db():
        conn = sqlite3.connect(app.config['DATABASE'], timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    with db() as conn:
        conn.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS complaints (
          reference TEXT PRIMARY KEY, token_hash TEXT NOT NULL, title TEXT NOT NULL,
          category TEXT NOT NULL, location TEXT NOT NULL, description TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'Diterima', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS rate_limits (client TEXT PRIMARY KEY, window INTEGER, count INTEGER);
        ''')

    @app.before_request
    def guard():
        if request.path.startswith('/api/'):
            # TCP peer only: forwarded headers are deliberately not trusted.
            client = request.remote_addr or 'unknown'
            window = int(time.time()) // app.config['RATE_WINDOW']
            with db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                conn.execute('DELETE FROM rate_limits WHERE window < ?', (window,))
                conn.execute('''INSERT INTO rate_limits VALUES (?, ?, 1)
                  ON CONFLICT(client) DO UPDATE SET count=count+1''', (client, window))
                count = conn.execute('SELECT count FROM rate_limits WHERE client=?', (client,)).fetchone()[0]
            if count > app.config['RATE_LIMIT']:
                response = jsonify(error='Terlalu banyak permintaan. Coba kembali sebentar lagi.')
                response.status_code = 429
                response.headers['Retry-After'] = str(app.config['RATE_WINDOW'] - int(time.time()) % app.config['RATE_WINDOW'])
                return response
        if request.method == 'POST':
            if request.headers.get('Origin') and request.headers['Origin'] != request.host_url.rstrip('/'):
                return jsonify(error='Origin tidak diizinkan.'), 403
            if request.headers.get('X-Lab-Request') != '1':
                return jsonify(error='Header X-Lab-Request: 1 diperlukan.'), 403
            if not request.is_json:
                return jsonify(error='Gunakan Content-Type application/json.'), 415

    @app.after_request
    def headers(response):
        response.headers.update({
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
            'X-Frame-Options': 'DENY', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
            'Cache-Control': 'no-store'})
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.name), error.code

    def payload(fields):
        data = request.get_json()
        if not isinstance(data, dict) or set(data) != set(fields):
            raise ValueError('Kolom permintaan tidak sesuai.')
        for name, (minimum, maximum) in fields.items():
            value = data[name]
            if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
                raise ValueError(f'{name}: panjang harus {minimum}–{maximum} karakter.')
            data[name] = value.strip()
            if any(ord(c) < 32 and c not in '\n\t\r' for c in value):
                raise ValueError('Karakter kontrol tidak diperbolehkan.')
        return data

    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error=str(error)), 400

    @app.get('/')
    @app.get('/pengaduan')
    @app.get('/status')
    @app.get('/dokumen')
    def page():
        return render_template('index.html', categories=CATEGORIES, documents=DOCUMENTS)

    @app.get('/api/health')
    def health():
        with db() as conn:
            conn.execute('SELECT 1').fetchone()
        return jsonify(status='ok', environment='fictional-local-lab')

    @app.get('/api/categories')
    def categories():
        return jsonify(items=CATEGORIES)

    @app.get('/api/statistics')
    def statistics():
        return jsonify(source='fixed-fictional-demo', received=128, reviewing=36, resolved=92)

    @app.post('/api/complaints')
    def submit():
        data = payload({'title': (8, 120), 'category': (1, 40), 'location': (3, 100), 'description': (30, 3000)})
        if data['category'] not in CATEGORIES:
            raise ValueError('Kategori tidak dikenal.')
        reference = 'RW-' + secrets.token_hex(8).upper()
        token = secrets.token_urlsafe(32)
        with db() as conn:
            conn.execute('INSERT INTO complaints(reference,token_hash,title,category,location,description) VALUES(?,?,?,?,?,?)',
                         (reference, hashlib.sha256(token.encode()).hexdigest(), data['title'], data['category'], data['location'], data['description']))
        return jsonify(reference=reference, access_token=token, status='Diterima'), 201

    @app.post('/api/complaints/status')
    def status():
        data = payload({'reference': (1, 40), 'access_token': (1, 100)})
        with db() as conn:
            row = conn.execute('SELECT reference,title,category,location,status,created_at FROM complaints WHERE reference=? AND token_hash=?',
                               (data['reference'], hashlib.sha256(data['access_token'].encode()).hexdigest())).fetchone()
        if row is None:
            return jsonify(error='Laporan atau kunci akses tidak ditemukan.'), 404
        return jsonify(dict(row))

    @app.get('/api/documents')
    def documents():
        query = request.args.get('q', '').strip()
        if len(query) > 100:
            raise ValueError('Pencarian maksimal 100 karakter.')
        return jsonify(items=[d for d in DOCUMENTS if query.casefold() in (d['title'] + d['description']).casefold()])

    @app.get('/api/documents/<document_id>/download')
    def download(document_id):
        document = next((d for d in DOCUMENTS if d['id'] == document_id), None)
        if document is None:
            return jsonify(error='Dokumen tidak ditemukan.'), 404
        body = f"RUANG WARGA — DOKUMEN FIKTIF UNTUK LAB\n\n{document['title']}\n\n{document['description']}\n\nBukan layanan pengaduan resmi. Jangan memasukkan data pribadi atau laporan nyata.\n\n1. Isi laporan simulasi.\n2. Simpan nomor laporan dan kunci akses.\n3. Periksa status menggunakan keduanya.\n\nStatus awal: Diterima. Tidak ada petugas nyata atau pemrosesan otomatis.\n"
        return Response(body, content_type='text/plain; charset=utf-8', headers={'Content-Disposition': f'attachment; filename="{document_id}.txt"'})

    return app

if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=8000, debug=False)
