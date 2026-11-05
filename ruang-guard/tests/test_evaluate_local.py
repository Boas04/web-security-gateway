"""Offline checks for the evaluator's target, privacy, and stop boundaries."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch


SPEC = importlib.util.spec_from_file_location(
    'ruang_guard_local_evaluator', Path(__file__).with_name('evaluate_local.py'))
evaluator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluator)


class LocalEvaluationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temp_root = Path(temporary.name)
        # Evaluation resolves its output relative to __file__; all artifacts stay
        # in this temporary directory, including results from an interrupted run.
        file_patch = patch.object(
            evaluator, '__file__', str(self.temp_root / 'project' / 'tests' / 'evaluate_local.py'))
        file_patch.start()
        self.addCleanup(file_patch.stop)

        # Even a future accidental unmocked transport must not reach the network.
        network_patch = patch('socket.socket.connect', side_effect=AssertionError('Network forbidden in offline tests'))
        network_patch.start()
        self.addCleanup(network_patch.stop)
        session_patch = patch.object(evaluator.requests, 'Session')
        self.session_factory = session_patch.start()
        self.addCleanup(session_patch.stop)
        self.client = MagicMock()
        self.session_factory.return_value.__enter__.return_value = self.client
        self.response = MagicMock()
        self.response.__enter__.return_value = self.response
        self.response.status_code = 200
        self.response.headers = {}
        self.response.json.return_value = {'environment': 'fictional-local-lab', 'status': 'ok'}
        self.client.request.return_value = self.response

        self.stdout = io.StringIO()
        stdout_patch = patch('sys.stdout', self.stdout)
        stdout_patch.start()
        self.addCleanup(stdout_patch.stop)
        self.evaluation = evaluator.Evaluation()

    def test_fixed_loopback_transport_and_no_redirect_or_environment_credentials(self):
        row, identity = self.evaluation.send('preflight', 'health')

        self.assertTrue(identity)
        self.assertEqual(row['status'], 200)
        args, kwargs = self.client.request.call_args
        self.assertEqual(args, ('GET', 'http://127.0.0.1:8090/api/health'))
        self.assertEqual(kwargs['headers']['Host'], 'localhost:8090')
        self.assertIs(kwargs['allow_redirects'], False)
        self.assertIs(self.client.trust_env, False)
        self.assertTrue(all(0 < value <= 8 for value in kwargs['timeout']))

    def test_sensitive_request_response_and_query_are_not_persisted(self):
        markers = {
            'description': 'fictional-complaint-body-marker',
            'access_token': 'fictional-access-token-marker',
            'authorization': 'fictional-authorization-marker',
            'cookie': 'fictional-cookie-marker',
            'query': 'fictional-private-query-marker',
            'response': 'fictional-response-body-marker',
        }
        self.response.json.return_value = {
            'error': markers['response'],
            'access_token': markers['access_token'],
            'description': markers['description'],
        }
        row, _ = self.evaluation.send(
            'privacy', 'fixture', '/api/complaints?fixture=' + markers['query'], 'POST',
            json={'description': markers['description'], 'access_token': markers['access_token']},
            headers={'Authorization': 'Bearer ' + markers['authorization'], 'Cookie': markers['cookie']})

        self.assertIsNone(row['reason'])
        self.assertEqual(set(row), {
            'number', 'at', 'phase', 'case', 'status', 'reason', 'retry_after', 'latency_ms'})
        persisted = (self.evaluation.output / 'responses.jsonl').read_text(encoding='utf-8')
        serialized = persisted + json.dumps(self.evaluation.rows) + self.stdout.getvalue()
        for marker in markers.values():
            self.assertNotIn(marker, serialized)
        self.assertEqual(json.loads(persisted), row)

    def test_wrong_portal_identity_stops_before_sending_any_payload(self):
        self.response.json.return_value = {'environment': 'another-service', 'status': 'ok'}

        self.assertFalse(self.evaluation.run())

        self.client.request.assert_called_once()
        args, kwargs = self.client.request.call_args
        self.assertEqual(args, ('GET', 'http://127.0.0.1:8090/api/health'))
        self.assertNotIn('json', kwargs)
        self.assertNotIn('data', kwargs)
        self.assertNotIn('params', kwargs)
        self.assertEqual([row['phase'] for row in self.evaluation.rows], ['preflight'])
        result = json.loads((self.evaluation.output / 'results.json').read_text(encoding='utf-8'))
        self.assertEqual(result['status'], 'stopped')
        self.assertEqual(result['total_requests'], 1)
        self.assertEqual(result['checks'], [])

    def test_request_budget_stops_before_creating_http_client(self):
        self.evaluation.count = evaluator.MAX_REQUESTS

        with self.assertRaises(RuntimeError):
            self.evaluation.send('budget', 'over-limit')

        self.session_factory.assert_not_called()
        self.client.request.assert_not_called()
        self.assertEqual(self.evaluation.count, evaluator.MAX_REQUESTS)
        self.assertEqual(self.evaluation.rows, [])
        self.assertFalse((self.evaluation.output / 'responses.jsonl').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
