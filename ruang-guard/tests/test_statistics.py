"""Statistics endpoint checks against temporary metadata; no live traffic."""
import json
from pathlib import Path
import tempfile
import unittest

from werkzeug.security import generate_password_hash

from guard.admin import create_app
from guard.core import Store


class StatisticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = 'statistics-test-only'
        cls.password_hash = generate_password_hash(cls.password, method='scrypt')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.now = 1_000_000.0
        self.store = Store(Path(temporary.name) / 'events.db', 'test-only-key' * 4,
                           {'portal': {'address': '172.30.10.10', 'port': 8000,
                                       'health_path': '/api/health'}}, now=lambda: self.now)
        self.client = create_app(self.store, self.password_hash).test_client()

    def login(self):
        csrf = self.client.get('/admin/api/session').json['csrf']
        response = self.client.post('/admin/api/login', json={'password': self.password},
                                    headers={'X-CSRF-Token': csrf})
        self.assertEqual(response.status_code, 200)

    def event(self, at, client='a' * 24, decision='allowed', reason='forwarded',
              route='/api/health', rules=()):
        with self.store.db() as db:
            cursor = db.execute(
                'INSERT INTO events(at,client,method,route,status,decision,reason,rules,ms) '
                'VALUES(?,?,?,?,?,?,?,?,?)',
                (at, client, 'GET', route, 403 if decision == 'blocked' else 200,
                 decision, reason, json.dumps(rules), 12.5))
            return cursor.lastrowid

    def get(self, **params):
        response = self.client.get('/admin/api/statistics', query_string=params)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.json

    def database_dump(self):
        with self.store.db() as db:
            return '\n'.join(db.iterdump())

    def test_requires_admin_and_preserves_security_headers(self):
        self.assertEqual(self.client.get('/admin/api/statistics').status_code, 401)
        self.login()
        response = self.client.get('/admin/api/statistics')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertIn("script-src 'self'", response.headers['Content-Security-Policy'])
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
        self.now += 3601
        self.assertEqual(self.client.get('/admin/api/statistics').status_code, 401)

    def test_validates_all_filter_and_pagination_inputs(self):
        self.login()
        invalid = [dict(range='30d'), dict(q='x' * 201), dict(q='\0'), dict(page='0'),
                   dict(page='-1'), dict(page='1.0'), dict(page='1000001'),
                   dict(page='١'), dict(page_size='7'), dict(page_size='-10'),
                   dict(unknown='x'), [('range', '15m'), ('range', '7d')]]
        for params in invalid:
            with self.subTest(params=params):
                self.assertEqual(self.client.get('/admin/api/statistics', query_string=params).status_code, 400)
        for selected, seconds, buckets in [('15m', 30, 30), ('1h', 120, 30),
                                            ('24h', 3600, 24), ('7d', 21600, 28)]:
            with self.subTest(selected=selected):
                result = self.get(range=selected)
                self.assertEqual(result['bucket_seconds'], seconds)
                self.assertEqual(len(result['buckets']), buckets)

    def test_aggregates_more_than_overview_limit_and_paginates_coherently(self):
        ids = [self.event(self.now - index, decision='blocked' if index % 2 else 'allowed',
                          reason='waf_rule' if index % 2 else 'forwarded', rules=[941100] if index % 2 else [])
               for index in range(125)]
        self.login()
        result = self.get(page='2', page_size='25')
        self.assertEqual(len(self.client.get('/admin/api/overview').json['events']), 100)
        self.assertEqual(result['totals'], dict(total=125, allowed=63, blocked=62, errors=0, active_sources=1))
        self.assertEqual(sum(bucket['total'] for bucket in result['buckets']), 125)
        self.assertEqual(result['pagination'], dict(page=2, page_size=25, total=125, pages=5))
        self.assertEqual([row['id'] for row in result['events']], ids[25:50])
        self.assertEqual(result['events'][0]['rules'], [941100])
        self.assertEqual(result['reasons'], [dict(reason='waf_rule', count=62)])
        final = self.get(page='99999', page_size='100')
        self.assertEqual(final['pagination']['page'], 2)
        self.assertEqual(len(final['events']), 25)

    def test_range_boundaries_future_and_bucket_edges(self):
        start = self.now - 900
        self.event(start - .001)
        first = self.event(start)
        self.event(start + 29.999)
        boundary = self.event(start + 30)
        last = self.event(self.now)
        self.event(self.now + .001)
        self.login()
        result = self.get()
        self.assertEqual(result['totals']['total'], 4)
        self.assertEqual([row['id'] for row in result['events']], [last, boundary, first + 1, first])
        self.assertEqual(result['buckets'][0]['total'], 2)
        self.assertEqual(result['buckets'][1]['total'], 1)
        self.assertEqual(result['buckets'][-1]['total'], 1)
        self.assertEqual(result['buckets'][0]['at'], start)
        self.assertEqual(result['buckets'][-1]['at'], self.now - 30)
        self.assertEqual(self.get(range='1h')['totals']['total'], 5)

    def test_search_is_literal_and_applies_to_every_aggregate(self):
        self.event(self.now, client='a' * 24, decision='blocked', reason='waf_rule', rules=[941100])
        self.event(self.now, client='b' * 24, reason='forwarded')
        self.event(self.now, client='c' * 24, decision='blocked', reason='test%_\\literal', rules=[942100])
        self.login()
        for query in ['WAF_RULE', '941100', 'a' * 24]:
            with self.subTest(query=query):
                result = self.get(q=query)
                self.assertEqual(result['totals']['total'], 1)
                self.assertEqual(result['totals']['blocked'], 1)
                self.assertEqual(len(result['events']), 1)
                self.assertEqual(len(result['sources']), 1)
                self.assertEqual(result['sources'][0]['client'], 'a' * 24)
                self.assertEqual(result['reasons'], [dict(reason='waf_rule', count=1)])
                self.assertEqual(sum(bucket['total'] for bucket in result['buckets']), 1)
        for query in ['%', '_\\', "' OR '1'='1", 'not-present']:
            with self.subTest(query=query):
                expected = 1 if query in ['%', '_\\'] else 0
                self.assertEqual(self.get(q=query)['totals']['total'], expected)
        self.assertEqual(self.get(q='GET')['totals']['total'], 3)
        self.assertEqual(self.get(q='403')['totals']['total'], 2)

    def test_distinct_sources_per_bucket_and_deterministic_top_ten(self):
        for index in range(12):
            self.event(self.now - 1, client=f'{index:024x}')
        self.event(self.now - 2, client=f'{0:024x}', decision='error', reason='origin_unavailable')
        self.event(self.now - 31, client=f'{0:024x}')
        self.login()
        result = self.get()
        self.assertEqual(result['totals']['active_sources'], 12)
        self.assertEqual(result['totals']['errors'], 1)
        self.assertEqual(result['buckets'][-1]['active_sources'], 12)
        self.assertEqual(result['buckets'][-2]['active_sources'], 1)
        self.assertEqual(len(result['sources']), 10)
        self.assertEqual(result['sources'][0], dict(client=f'{0:024x}', total=3, allowed=2, blocked=0, errors=1))
        self.assertEqual(result['sources'][1]['client'], f'{1:024x}')

    def test_empty_state_read_only_and_no_sensitive_fields(self):
        self.login()
        before = self.database_dump()
        result = self.get()
        self.assertEqual(self.database_dump(), before)
        self.assertEqual(result['totals'], dict(total=0, allowed=0, blocked=0, errors=0, active_sources=0))
        self.assertEqual(result['pagination'], dict(page=1, page_size=25, total=0, pages=0))
        self.assertFalse(result['events'] or result['sources'] or result['reasons'])
        self.assertTrue(all(bucket['total'] == 0 for bucket in result['buckets']))
        self.event(self.now, client=self.store.identity('192.0.2.123'))
        before = self.database_dump()
        result = self.get()
        self.assertEqual(self.database_dump(), before)
        self.assertEqual(set(result['events'][0]),
                         {'id', 'at', 'client', 'method', 'route', 'status', 'decision', 'reason', 'rules', 'ms'})
        serialized = json.dumps(result)
        for secret in ['192.0.2.123', self.password, self.password_hash, self.store.secret,
                       'csrf', 'access_token', 'description', 'payload']:
            self.assertNotIn(secret, serialized)


if __name__ == '__main__':
    unittest.main(verbosity=2)
