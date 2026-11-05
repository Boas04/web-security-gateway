"""Bounded HTTP evaluation of this local lab only; never accepts a target URL.

Does not read secrets, log bodies, change settings, or operate Docker.
Run explicitly: python tests/evaluate_local.py
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone, timedelta
import json
import math
from pathlib import Path
import threading
import time

import requests

BASE = 'http://127.0.0.1:8090'
PUBLIC = 'http://localhost:8090'
WIB = timezone(timedelta(hours=7))
MAX_REQUESTS, MAX_SECONDS = 450, 540
BURST_COUNT, BURST_RATE, WORKERS = 200, 20, 5
SAFE_REASONS = {'security_restriction', 'too_many_requests', 'unsupported_format',
                'not_found', 'request_too_large', 'service_unavailable', 'invalid_request'}


def stamp():
    return datetime.now(WIB).isoformat(timespec='seconds')


def stats(rows):
    times = sorted(r['latency_ms'] for r in rows)
    def percentile(fraction):
        return times[max(0, math.ceil(len(times) * fraction) - 1)] if times else None
    return {'count': len(rows), 'http_status': dict(Counter(str(r['status']) for r in rows)),
            'p50_ms': percentile(.50), 'p95_ms': percentile(.95),
            'max_ms': max(times) if times else None}


class Evaluation:
    def __init__(self):
        self.started = time.monotonic()
        self.started_at = stamp()
        self.output = Path(__file__).resolve().parents[2] / (
            'ruang-guard-evaluation-' + datetime.now(WIB).strftime('%Y%m%d-%H%M%S-%f'))
        self.output.mkdir()
        self.lock = threading.Lock()
        self.abort = threading.Event()
        self.rows, self.checks = [], []
        self.count = self.failures = 0
        self.status, self.failure = 'running', None
        self.burst_elapsed = None

    def send(self, phase, case, path='/api/health', method='GET', **kwargs):
        with self.lock:
            if self.abort.is_set() or self.count >= MAX_REQUESTS or time.monotonic() - self.started >= MAX_SECONDS:
                raise RuntimeError('Evaluation budget reached or service errors detected')
            self.count += 1
            number = self.count
        headers = {'Host': 'localhost:8090', 'User-Agent': 'RuangGuard-Evaluation/1.0',
                   'Accept': 'application/json'}
        headers.update(kwargs.pop('headers', {}))
        started = time.monotonic()
        status, reason, retry, identity = 0, None, None, False
        try:
            with requests.Session() as client:
                client.trust_env = False
                with client.request(method, BASE + path, headers=headers,
                                    timeout=(2, 8), allow_redirects=False, **kwargs) as response:
                    status = response.status_code
                    raw_retry = response.headers.get('Retry-After', '')
                    if raw_retry.isdigit():
                        retry = int(raw_retry)
                    try:
                        body = response.json()
                    except ValueError:
                        body = {}
                    if isinstance(body, dict):
                        candidate = body.get('code')
                        reason = candidate if isinstance(candidate, str) and candidate in SAFE_REASONS else None
                        identity = body.get('environment') == 'fictional-local-lab' and body.get('status') == 'ok'
        except requests.RequestException:
            reason = 'connection_error'
        row = {'number': number, 'at': stamp(), 'phase': phase, 'case': case,
               'status': status, 'reason': reason, 'retry_after': retry,
               'latency_ms': round((time.monotonic() - started) * 1000, 2)}
        with self.lock:
            self.rows.append(row)
            with (self.output / 'responses.jsonl').open('a', encoding='utf-8') as log:
                log.write(json.dumps(row) + '\n')
            if status == 0 or status >= 500:
                self.failures += 1
                if self.failures >= 3:
                    self.abort.set()
        return row, identity

    def check(self, name, passed, **details):
        item = {'name': name, 'passed': bool(passed), **details}
        self.checks.append(item)
        print(json.dumps(item), flush=True)

    def expect(self, name, row, status, reason=None):
        self.check(name, row['status'] == status and (reason is None or row['reason'] == reason),
                   expected=status, actual=row['status'], reason=row['reason'])

    def pause(self, seconds):
        if seconds > 120 or time.monotonic() - self.started + seconds >= MAX_SECONDS:
            raise RuntimeError('Block exceeds evaluation time budget')
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            print(json.dumps({'waiting_for_expiry_seconds': math.ceil(remaining)}), flush=True)
            time.sleep(min(20, remaining))

    def ready(self, phase):
        for _ in range(3):
            row, identity = self.send(phase, 'health')
            if row['status'] == 200 and identity:
                return row
            if row['status'] == 429:
                self.pause((row['retry_after'] or 5) + 1)
            else:
                raise RuntimeError('Local fictional portal identity or health could not be confirmed')
        raise RuntimeError('Service did not recover within bounded checks')

    def run(self):
        print(json.dumps({'target': PUBLIC, 'output': str(self.output),
                          'max_requests': MAX_REQUESTS, 'burst_requests': BURST_COUNT,
                          'burst_per_second': BURST_RATE, 'concurrency': WORKERS}), flush=True)
        try:
            self.ready('preflight')
            queries = ['privasi', 'panduan', 'lingkungan', "O'Connor", '1 < 2',
                       'taman & lampu', 'SELECT kegiatan komunitas']
            for index, query in enumerate(queries):
                row, _ = self.send('baseline', 'benign-query-' + str(index + 1),
                                   '/api/documents', params={'q': query})
                self.expect('benign-query-' + str(index + 1), row, 200)
                if row['status'] in (403, 429):
                    self.ready('baseline-recovery')
            for index in range(14):
                path = '/api/health' if index % 2 == 0 else '/api/categories'
                row, _ = self.send('baseline', 'normal-' + str(index + 1), path)
                self.expect('normal-' + str(index + 1), row, 200)
                if row['status'] in (403, 429):
                    self.ready('baseline-recovery')
            policy_cases = [
                ('foreign-origin', '/api/complaints', 'POST', 403, 'security_restriction',
                 {'json': {}, 'headers': {'Origin': 'https://example.invalid'}}),
                ('unsupported-compression', '/api/complaints', 'POST', 415,
                 'unsupported_format', {'data': b'test', 'headers': {'Content-Encoding': 'gzip'}}),
                ('admin-on-public', '/admin/api/overview', 'GET', 404, 'not_found', {}),
                ('oversized-body', '/api/complaints', 'POST', 413, None,
                 {'data': b'x' * 17000, 'headers': {'Content-Type': 'application/octet-stream'}}),
            ]
            for name, path, method, status, reason, kwargs in policy_cases:
                row, _ = self.send('policy', name, path, method, **kwargs)
                self.expect(name, row, status, reason)
            self.ready('before-burst')
            started = time.monotonic()
            next_send = started
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                pending = set()
                for index in range(BURST_COUNT):
                    if len(pending) >= WORKERS:
                        done, pending = wait(pending, return_when=FIRST_COMPLETED)
                        for future in done:
                            future.result()
                    if self.abort.is_set():
                        raise RuntimeError('Service errors interrupted burst')
                    delay = next_send - time.monotonic()
                    if delay > 0:
                        time.sleep(delay)
                    pending.add(pool.submit(self.send, 'burst', 'bounded-health-burst'))
                    next_send = time.monotonic() + 1 / BURST_RATE
                for future in pending:
                    future.result()
            self.burst_elapsed = round(time.monotonic() - started, 2)
            burst = [row for row in self.rows if row['phase'] == 'burst']
            self.check('rate-limit-observed', any(r['status'] == 429 and r['reason'] == 'too_many_requests' for r in burst),
                       distribution=stats(burst), elapsed_seconds=self.burst_elapsed)
            row, _ = self.send('rate-limit', 'forged-forwarded-address', headers={'X-Forwarded-For': '192.0.2.55'})
            self.expect('forwarded-header-does-not-clear-rate-block', row, 429, 'too_many_requests')
            self.ready('burst-recovery')
            waf_cases = [
                ('sqli-query', 'GET', {'params': {'q': "1' OR '1'='1' --"}}),
                ('xss-query', 'GET', {'params': {'q': '<script>alert(1)</script>'}}),
                ('xss-json', 'POST', {'json': {'description': '<script>alert(1)</script>'},
                 'headers': {'X-Lab-Request': '1', 'Origin': PUBLIC}}),
            ]
            for name, method, kwargs in waf_cases:
                self.ready('before-' + name)
                path = '/api/documents' if method == 'GET' else '/api/complaints'
                row, _ = self.send('waf', name, path, method, **kwargs)
                self.expect(name, row, 403, 'security_restriction')
                if row['status'] == 403 and row['reason'] == 'security_restriction':
                    blocked, _ = self.send('temporary-block', name + '-normal-request')
                    self.expect(name + '-temporary-block', blocked, 429, 'too_many_requests')
                    forged, _ = self.send('temporary-block', name + '-forwarded-header',
                                          headers={'X-Forwarded-For': '192.0.2.56'})
                    self.expect(name + '-forwarded-header', forged, 429, 'too_many_requests')
                    self.check(name + '-retry-after',
                               isinstance(forged['retry_after'], int) and isinstance(blocked['retry_after'], int)
                               and 0 < forged['retry_after'] <= blocked['retry_after'])
                recovered = self.ready(name + '-recovery')
                self.expect(name + '-recovered', recovered, 200)
            self.expect('final-health', self.ready('final-health'), 200)
            self.status = 'completed'
        except Exception as error:
            self.status, self.failure = 'stopped', type(error).__name__
            print(json.dumps({'stopped': self.failure}), flush=True)
        finally:
            result = {'started_at': self.started_at, 'finished_at': stamp(), 'status': self.status,
                      'failure': self.failure, 'target': PUBLIC, 'transport': BASE,
                      'bounds': {'max_requests': MAX_REQUESTS, 'max_seconds': MAX_SECONDS,
                                 'workers': WORKERS, 'burst_requests': BURST_COUNT, 'burst_rps': BURST_RATE},
                      'total_requests': self.count, 'elapsed_seconds': round(time.monotonic() - self.started, 2),
                      'overall': stats(self.rows), 'burst_elapsed_seconds': self.burst_elapsed,
                      'phases': {p: stats([r for r in self.rows if r['phase'] == p]) for p in sorted({r['phase'] for r in self.rows})},
                      'burst_by_status': {str(s): stats([r for r in self.rows if r['phase'] == 'burst' and r['status'] == s])
                                          for s in sorted({r['status'] for r in self.rows if r['phase'] == 'burst'})},
                      'checks': self.checks}
            (self.output / 'results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
            print(json.dumps({'output': str(self.output), 'status': self.status, 'total': self.count,
                              'passed': sum(c['passed'] for c in self.checks),
                              'failed': sum(not c['passed'] for c in self.checks)}), flush=True)
        return self.status == 'completed' and all(c['passed'] for c in self.checks)


if __name__ == '__main__':
    raise SystemExit(0 if Evaluation().run() else 1)
