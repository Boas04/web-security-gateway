"""Independent fictional catalog origin; no connection to real organizations."""
import sqlite3
from pathlib import Path
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

ITEMS=[(1,'Buku Catatan Imaji','Alat tulis'),(2,'Lampu Meja Rekaan','Peralatan'),(3,'Tas Kanvas Contoh','Perlengkapan'),(4,'Pensil Warna Fiktif','Alat tulis'),(5,'Rak Buku Mini','Peralatan'),(6,'Botol Minum Contoh','Perlengkapan')]

def create_app():
    app=Flask(__name__, root_path=str(Path(__file__).resolve().parent))
    app.config.update(TRUSTED_HOSTS=['localhost','127.0.0.1','[::1]'],MAX_CONTENT_LENGTH=16384)
    def items():
        query=request.args.get('q','')
        if len(query)>100 or any(ord(c)<32 for c in query):
            raise ValueError('Pencarian maksimal 100 karakter.')
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE items(id INTEGER,name TEXT,category TEXT)')
            db.executemany('INSERT INTO items VALUES(?,?,?)',ITEMS)
            rows=db.execute('SELECT id,name,category FROM items WHERE instr(lower(name),lower(?))>0 ORDER BY id',(query,)).fetchall()
        return [dict(id=r[0],name=r[1],category=r[2]) for r in rows]
    @app.get('/')
    def home():return render_template('index.html',items=items(),query=request.args.get('q',''))
    @app.get('/api/items')
    def catalog():return jsonify(application='katalog-lab',items=items())
    @app.get('/api/health')
    def health():return jsonify(environment='fictional-local-lab',application='katalog-lab',status='ok')
    @app.errorhandler(ValueError)
    def invalid(error):return jsonify(error='Pencarian tidak valid.'),400
    @app.errorhandler(HTTPException)
    def http_error(error):return jsonify(error=error.name),error.code
    @app.after_request
    def secure(response):
        response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'none'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        return response
    return app
