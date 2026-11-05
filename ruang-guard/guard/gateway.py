"""Bounded reverse proxy. All requests require an affirmative Coraza verdict."""
import base64
import os
import time
from urllib.parse import urlsplit

from flask import Flask, Response, jsonify, request, render_template
import requests
from werkzeug.exceptions import HTTPException

from .core import load_store, http_session, origin_url

HOP = {'connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade','content-length','forwarded','x-forwarded-for','x-forwarded-host','x-forwarded-proto','x-real-ip','x-request-id','x-original-url','x-rewrite-url'}
PUBLIC_ORIGINS = frozenset({'http://localhost:8090', 'http://127.0.0.1:8090'})


def filtered(headers):
    excluded = HOP | {v.strip().lower() for v in headers.get('Connection', '').split(',')}
    return {k:v for k,v in headers.items() if k.lower() not in excluded}


def create_app(store=None, session_factory=http_session, inspector=None):
    store = store or load_store()
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=16384, TRUSTED_HOSTS=['localhost','127.0.0.1','[::1]'])
    public_origin = os.getenv('PUBLIC_ORIGIN', 'http://localhost:8090')
    host = urlsplit(public_origin).netloc
    if public_origin not in PUBLIC_ORIGINS:
        raise ValueError('This lab supports only the documented loopback public origin.')
    waf_url = os.getenv('WAF_URL', 'http://waf:8081/inspect')

    def inspect(prepared, body, peer):
        with session_factory() as client:
            result = client.post(waf_url, json=dict(method=prepared.method, uri=prepared.path_url, headers=dict(prepared.headers), body=base64.b64encode(body).decode(), client=peer), timeout=(2, 5))
            if result.status_code != 200 or len(result.content) > 65536:
                raise ValueError('WAF unavailable')
            verdict = result.json()
            if type(verdict.get('allowed')) is not bool or not isinstance(verdict.get('rules'), list) or len(verdict['rules']) > 200 or any(type(i) is not int for i in verdict['rules']):
                raise ValueError('Invalid WAF verdict')
            return verdict

    def public_error(status, retry=None):
        if status >= 500:
            code, message = 'service_unavailable', 'Layanan sementara tidak tersedia. Silakan coba beberapa saat lagi.'
        elif status == 429:
            code = 'too_many_requests'
            message = f'Terlalu banyak permintaan. Coba lagi dalam {retry} detik.' if retry else 'Terlalu banyak permintaan. Silakan coba beberapa saat lagi.'
        elif status == 403:
            code, message = 'security_restriction', 'Permintaan tidak dapat diproses karena pembatasan keamanan.'
        elif status == 404:
            code, message = 'not_found', 'Halaman yang Anda cari tidak tersedia.'
        elif status == 413:
            code, message = 'request_too_large', 'Data yang dikirim terlalu besar. Kurangi ukuran data lalu coba lagi.'
        elif status == 415:
            code, message = 'unsupported_format', 'Format permintaan tidak didukung. Gunakan format yang sesuai lalu coba lagi.'
        else:
            code, message = 'invalid_request', 'Permintaan tidak dapat diproses. Periksa kembali data yang dikirim.'
        # API responses stay JSON; browser navigation gets a readable page.
        if not request.path.startswith('/api/') and request.accept_mimetypes['text/html'] > request.accept_mimetypes['application/json']:
            response = Response(render_template('public_error.html', message=message, status=status), mimetype='text/html')
        else:
            response = jsonify(error=message, code=code)
        response.status_code = status
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        if retry:
            response.headers['Retry-After'] = str(retry)
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return public_error(error.code)

    @app.errorhandler(Exception)
    def internal_error(error):
        # Fail closed without Flask's exception logger exposing request URLs.
        return public_error(503)

    @app.route('/', defaults={'path':''}, methods=['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'])
    @app.route('/<path:path>', methods=['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'])
    def proxy(path):
        started = time.monotonic()
        peer = request.remote_addr or 'unknown'  # Never ProxyFix / client-supplied forwarding headers.
        client_id = store.identity(peer)
        selected_origin = store.settings()['origin']
        rules = []

        def finish(response, decision, reason):
            store.event(client_id, request.method, request.path, response.status_code, decision, reason, rules, (time.monotonic()-started)*1000, origin=selected_origin)
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['Cache-Control'] = 'no-store'
            return response

        def reject(status, reason, retry=None, decision='blocked'):
            response = public_error(status, retry)
            return finish(response, decision, reason)

        retry, reason = store.limit(client_id)
        if retry:
            return reject(429, reason, retry)
        if request.path.startswith('/admin'):
            return reject(404, 'admin_not_on_public_listener')
        if request.headers.get('Content-Encoding', 'identity').lower() != 'identity':
            return reject(415, 'compressed_request_not_supported')
        # Normalize Origin to the configured canonical lab host, without trusting arbitrary values.
        incoming_origin = request.headers.get('Origin')
        if incoming_origin and incoming_origin not in PUBLIC_ORIGINS:
            return reject(403, 'origin_not_allowed')
        try:
            body = request.get_data()
        except HTTPException:
            return reject(413, 'body_too_large')
        headers = filtered(request.headers)
        headers['Host'] = host
        headers['Accept-Encoding'] = 'identity'
        if incoming_origin:
            headers['Origin'] = public_origin
        # Admin cookies must never be passed to a customer origin, even if forged into this path.
        if 'Cookie' in headers:
            headers['Cookie'] = '; '.join(c for c in headers['Cookie'].split(';') if c.strip().split('=',1)[0] != 'rg_session')
        origin = store.origins[selected_origin]
        # Absolute base is constant; neither Host nor URL parameters select the destination.
        url = origin_url(origin) + request.full_path.rstrip('?')
        try:
            prepared = requests.Request(request.method, url, headers=headers, data=body).prepare()
            verdict = (inspector or inspect)(prepared, body, peer)
            rules = verdict['rules']
            if not verdict['allowed']:
                store.block(client_id, 'waf_rule')
                return reject(403, 'waf_rule')
        except (requests.RequestException, ValueError, KeyError, TypeError):
            return reject(503, 'waf_unavailable', decision='error')
        try:
            with session_factory() as client:
                with client.send(prepared, timeout=(2, 8), allow_redirects=False, stream=True) as upstream:
                    content = bytearray()
                    for chunk in upstream.iter_content(65536):
                        content.extend(chunk)
                        if len(content) > 2 * 1024 * 1024:
                            return reject(502, 'response_too_large', decision='error')
                    outgoing = filtered(upstream.headers)
                    outgoing.pop('Content-Encoding', None)
                    response = Response(bytes(content), status=upstream.status_code, headers=outgoing)
            return finish(response, 'allowed', 'forwarded')
        except requests.RequestException:
            return reject(502, 'origin_unavailable', decision='error')
    return app
