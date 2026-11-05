"""Block expiry must behave identically whichever worker handles it first."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import unittest

from guard.core import Store


class BlockExpiryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.now = 1000.0
        self.store = Store(Path(temporary.name) / 'guard.db', 'test-only-key' * 4,
                           {'portal': {'address': '172.30.10.10', 'port': 8000,
                                       'health_path': '/api/health'}}, now=lambda: self.now)
        self.store.update('portal', 2, 60, 2)

    def block(self, client, login=False):
        for _ in range(5 if login else 2):
            self.assertEqual(self.store.limit(client, login=login), (0, ''))
        self.assertEqual(self.store.limit(client, login=login),
                         (300, 'login_limit') if login else (2, 'rate_limit'))

    def row(self, table, client):
        self.assertIn(table, {'blocks', 'counters'})
        with self.store.db() as db:
            row = db.execute(f'SELECT * FROM {table} WHERE client=?', (client,)).fetchone()
            return dict(row) if row else None

    def assert_fresh(self, client):
        self.assertIsNone(self.row('blocks', client))
        self.assertEqual(self.row('counters', client),
                         dict(client=client, start=self.now, count=1))

    def test_cleanup_before_request_resets_expired_counter_inside_original_window(self):
        self.block('visitor')
        self.now = 1002.1
        self.store.cleanup()
        self.assertIsNone(self.row('counters', 'visitor'))
        self.assertEqual(self.store.limit('visitor'), (0, ''))
        self.assert_fresh('visitor')

    def test_request_before_cleanup_keeps_new_counter(self):
        self.block('visitor')
        self.now = 1002.1
        self.assertEqual(self.store.limit('visitor'), (0, ''))
        self.store.cleanup()
        self.assert_fresh('visitor')
        self.assertEqual(self.store.limit('visitor'), (0, ''))
        self.assertEqual(self.store.limit('visitor'), (4, 'rate_limit'))

    def test_exact_expiry_boundary_resets_counter(self):
        self.block('visitor')
        self.now = 1002.0
        self.store.cleanup()
        self.assertIsNone(self.row('blocks', 'visitor'))
        self.assertIsNone(self.row('counters', 'visitor'))
        self.assertEqual(self.store.limit('visitor'), (0, ''))
        self.assert_fresh('visitor')

    def test_active_block_and_counter_are_preserved_without_extending_expiry(self):
        self.block('visitor')
        expected_block = self.row('blocks', 'visitor')
        expected_counter = self.row('counters', 'visitor')
        self.now = 1001.0
        self.store.cleanup()
        self.assertEqual(self.store.limit('visitor'), (1, 'rate_limit'))
        self.assertEqual(self.row('blocks', 'visitor'), expected_block)
        self.assertEqual(self.row('counters', 'visitor'), expected_counter)

    def test_expiry_does_not_reset_other_sources_or_unblocked_counters(self):
        self.block('expired')
        self.assertEqual(self.store.limit('unblocked'), (0, ''))
        unrelated = self.row('counters', 'unblocked')
        self.now = 1001.0
        self.block('active')
        active = self.row('counters', 'active')
        self.now = 1002.1
        self.store.cleanup()
        self.assertIsNone(self.row('blocks', 'expired'))
        self.assertIsNone(self.row('counters', 'expired'))
        self.assertEqual(self.row('counters', 'active'), active)
        self.assertEqual(self.row('counters', 'unblocked'), unrelated)
        self.assertEqual(self.store.limit('active'), (1, 'rate_limit'))
        self.assertEqual(self.store.limit('unblocked'), (0, ''))
        self.assertEqual(self.store.limit('unblocked'), (2, 'rate_limit'))

    def test_login_namespace_expiry_does_not_remove_current_visitor_counter(self):
        self.block('same-source', login=True)
        self.now = 1299.0
        self.assertEqual(self.store.limit('same-source'), (0, ''))
        visitor = self.row('counters', 'same-source')
        self.now = 1300.0
        self.store.cleanup()
        self.assertIsNone(self.row('counters', 'login:same-source'))
        self.assertIsNone(self.row('blocks', 'login:same-source'))
        self.assertEqual(self.row('counters', 'same-source'), visitor)
        self.assertEqual(self.store.limit('same-source', login=True), (0, ''))
        self.assert_fresh('login:same-source')

    def test_repeated_cleanup_does_not_remove_new_counter(self):
        self.block('visitor')
        self.now = 1002.1
        self.store.cleanup()
        self.store.cleanup()
        self.assertEqual(self.store.limit('visitor'), (0, ''))
        self.store.cleanup()
        self.store.cleanup()
        self.assert_fresh('visitor')

    def test_parallel_cleanup_and_request_preserve_fresh_window(self):
        for index in range(10):
            client = 'visitor-' + str(index)
            self.now = 2000.0 + index * 10
            self.block(client)
            self.now += 2.1
            start = threading.Barrier(2)

            def cleanup():
                start.wait(timeout=5)
                self.store.cleanup()

            def request():
                start.wait(timeout=5)
                return self.store.limit(client)

            with ThreadPoolExecutor(max_workers=2) as pool:
                clean = pool.submit(cleanup)
                result = pool.submit(request)
                self.assertEqual(result.result(timeout=15), (0, ''))
                clean.result(timeout=15)
            self.assert_fresh(client)


if __name__ == '__main__':
    unittest.main(verbosity=2)
