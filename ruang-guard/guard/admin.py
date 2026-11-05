"""Admin listener: server-side sessions, CSRF, exact-origin writes, no public proxy route."""
import hashlib
import hmac
import os
from pathlib import Path
import secrets
from functools import wraps

from flask import Flask, Response, jsonify, render_template, request, g
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash

from .core import load_store
from .statistics import summarize
from .reports import export
from . import alerts, ml


def create_app(store=None, password_hash=None):
    store = store or load_store()
    alerts.initialize(store)
    ml.initialize(store)
    password_hash = password_hash or Path(os.getenv('PASSWORD_FILE', '/run/secrets/admin_hash')).read_text().strip()
    if not password_hash.startswith('scrypt:'):
        raise ValueError('Initialize an admin password with setup.py first.')
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=4096, TRUSTED_HOSTS=['localhost','127.0.0.1','[::1]'])

    def session(create=False):
        sid = request.cookies.get('rg_session', '')
        digest = hashlib.sha256(sid.encode()).hexdigest()
        with store.db() as db:
            row = db.execute('SELECT * FROM sessions WHERE sid=? AND expires>?', (digest, store.now())).fetchone()
        if row:
            return dict(row)
        if not create:
            return None
        return new_session(False)

    def new_session(authenticated):
        sid = secrets.token_urlsafe(32)
        row = dict(sid=hashlib.sha256(sid.encode()).hexdigest(), csrf=secrets.token_urlsafe(32), authenticated=int(authenticated), expires=store.now() + (3600 if authenticated else 600))
        with store.db(True) as db:
            # Bound pre-authentication storage even under anonymous session flooding.
            db.execute('DELETE FROM sessions WHERE expires < ?', (store.now(),))
            db.execute('DELETE FROM sessions WHERE sid IN (SELECT sid FROM sessions WHERE authenticated=0 ORDER BY expires DESC LIMIT -1 OFFSET 200)')
            db.execute('INSERT INTO sessions VALUES(:sid,:csrf,:authenticated,:expires)', row)
        g.new_cookie = sid
        return row

    def require_admin(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            active = session()
            if not active or not active['authenticated']:
                return jsonify(error='Silakan masuk terlebih dahulu.'), 401
            return fn(*args, **kwargs)
        return wrapped

    @app.before_request
    def csrf_guard():
        if request.method not in {'GET','HEAD','OPTIONS'}:
            active = session()
            origin = request.headers.get('Origin')
            if origin and origin != request.host_url.rstrip('/'):
                return jsonify(error='Origin ditolak.'), 403
            if not active or not hmac.compare_digest(request.headers.get('X-CSRF-Token',''), active['csrf']):
                return jsonify(error='Token CSRF tidak valid.'), 403
            if not request.is_json:
                return jsonify(error='JSON diperlukan.'), 415

    @app.after_request
    def secure(response):
        if getattr(g, 'new_cookie', None):
            response.set_cookie('rg_session', g.new_cookie, max_age=3600, httponly=True, secure=False, samesite='Strict', path='/admin')
        response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
                                 'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.name), error.code

    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error='Nilai konfigurasi tidak valid.'), 400

    @app.errorhandler(Exception)
    def internal_error(error):
        return jsonify(error='Layanan admin sementara tidak tersedia.'), 503

    @app.get('/admin/')
    def home():
        return render_template('dashboard.html')

    @app.get('/admin/api/session')
    def session_info():
        active = session(True)
        return jsonify(authenticated=bool(active['authenticated']), csrf=active['csrf'], expires=active['expires'])

    @app.post('/admin/api/login')
    def login():
        retry, _ = store.limit(store.identity(request.remote_addr or 'unknown'), login=True)
        if retry:
            return jsonify(error='Terlalu banyak percobaan masuk.'), 429, {'Retry-After':str(retry)}
        data = request.get_json()
        if not isinstance(data, dict) or not isinstance(data.get('password'), str) or len(data['password']) > 256:
            return jsonify(error='Kredensial tidak valid.'), 400
        if not check_password_hash(password_hash, data['password']):
            return jsonify(error='Kredensial tidak valid.'), 401
        active = session()
        with store.db(True) as db:
            db.execute('DELETE FROM sessions WHERE sid=?', (active['sid'],))
            db.execute('INSERT INTO audit(at,action,target) VALUES(?,?,?)', (store.now(), 'login', 'admin'))
        new = new_session(True)
        return jsonify(authenticated=True, csrf=new['csrf'])

    @app.post('/admin/api/logout')
    @require_admin
    def logout():
        with store.db(True) as db:
            db.execute('DELETE FROM sessions WHERE sid=?', (session()['sid'],))
        response = jsonify(ok=True)
        response.delete_cookie('rg_session', path='/admin')
        return response

    @app.get('/admin/api/overview')
    @require_admin
    def overview():
        return jsonify(store.snapshot())

    @app.get('/admin/api/statistics')
    @require_admin
    def statistics():
        return jsonify(summarize(store, request.args))

    @app.get('/admin/api/alerts')
    @require_admin
    def notification_list():
        return jsonify(alerts.snapshot(store))

    @app.post('/admin/api/alerts/ack')
    @require_admin
    def notification_ack():
        data = request.get_json()
        if not isinstance(data, dict) or set(data) != {'id'}:
            raise ValueError('Invalid notification')
        if not alerts.acknowledge(store, data['id']):
            return jsonify(error='Notifikasi tidak ditemukan.'), 404
        return jsonify(ok=True)

    @app.get('/admin/api/reports')
    @require_admin
    def reports():
        content, mime, suffix = export(store, request.args)
        return Response(content, content_type=mime, headers={'Content-Disposition': 'attachment; filename="ruang-guard-report.' + suffix + '"'})

    @app.get('/admin/api/ml')
    @require_admin
    def ml_status():
        return jsonify(ml.snapshot(store))

    @app.post('/admin/api/ml/<action>')
    @require_admin
    def ml_action(action):
        data=request.get_json()
        fields={'approve':{'ids'},'train':{'origin'},'activate':{'id'},'deactivate':{'id'},'review':{'id','verdict'},'respond':{'id'},'revoke':{'id'}}
        if action not in fields or not isinstance(data,dict) or set(data)!=fields[action]:
            return jsonify(error='Permintaan ML tidak valid.'),400
        try:
            if action=='approve':ml.approve(store,data['ids'])
            elif action=='train':
                if not isinstance(data['origin'],str):raise ValueError('Origin tidak valid.')
                return jsonify(id=ml.queue_training(store,data['origin'])),202
            elif action=='activate':ml.activate(store,data['id'])
            elif action=='deactivate':ml.deactivate(store,data['id'])
            elif action=='revoke':ml.revoke_baseline(store,data['id'])
            elif action=='respond':
                from .coordination import respond
                return jsonify(ok=True,applied=respond(store,data['id']))
            else:ml.review(store,data['id'],data['verdict'])
        except ValueError as error:
            return jsonify(error=str(error)),400
        return jsonify(ok=True)

    @app.post('/admin/api/settings')
    @require_admin
    def settings():
        data = request.get_json()
        if not isinstance(data, dict) or set(data) != {'origin','rate','window','duration'} or type(data['origin']) is not str or any(type(data[k]) is not int for k in ('rate','window','duration')):
            raise ValueError('Invalid fields')
        store.update(**data)
        return jsonify(ok=True)

    @app.post('/admin/api/unblock')
    @require_admin
    def unblock():
        data = request.get_json()
        if not isinstance(data, dict) or not isinstance(data.get('client'), str) or len(data['client']) > 32:
            raise ValueError('Invalid client')
        store.unblock(data['client'])
        return jsonify(ok=True)
    return app
