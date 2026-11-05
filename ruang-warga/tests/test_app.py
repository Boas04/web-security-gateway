import hashlib
from contextlib import closing
import sqlite3
import tempfile
import unittest
from app import create_app

class PortalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = self.temp.name + '/test.db'
        self.app = create_app({'TESTING': True, 'DATABASE': self.database, 'RATE_LIMIT': 500})
        self.client = self.app.test_client()
        self.headers = {'X-Lab-Request': '1'}
        self.data = dict(title='Lampu taman fiktif', category='Lingkungan', location='Kota Imaji', description='Lampu di taman rekaan tidak menyala pada malam simulasi.')

    def tearDown(self):
        self.temp.cleanup()

    def post(self, path, data):
        return self.client.post(path, json=data, headers=self.headers)

    def test_pages_and_headers(self):
        for path in ['/', '/pengaduan', '/status', '/dokumen']:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'DATA FIKTIF', response.data)
            self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])

    def test_submit_status_and_database_persistence(self):
        response = self.post('/api/complaints', self.data)
        self.assertEqual(response.status_code, 201)
        receipt = response.json
        query = {k: receipt[k] for k in ['reference','access_token']}
        other = create_app({'TESTING':True, 'DATABASE':self.database}).test_client()
        self.assertEqual(other.post('/api/complaints/status', json=query, headers=self.headers).json['title'], self.data['title'])
        with closing(sqlite3.connect(self.database)) as conn:
            stored = conn.execute('SELECT token_hash FROM complaints').fetchone()[0]
        self.assertNotEqual(stored, receipt['access_token'])
        self.assertEqual(stored, hashlib.sha256(receipt['access_token'].encode()).hexdigest())
        query['access_token'] = 'incorrect'
        self.assertEqual(self.post('/api/complaints/status',query).status_code,404)
        self.assertEqual(self.client.get('/api/complaints').status_code,405)

    def test_validation(self):
        for changes in [{'title':'x'},{'category':'Unknown'},{'description':None},{'location':['x']},{'extra':'bad'},{'title':'x'*121}]:
            self.assertEqual(self.post('/api/complaints',dict(self.data, **changes)).status_code,400)
        self.assertEqual(self.post('/api/complaints', []).status_code,400)
        self.assertEqual(self.post('/api/complaints',dict(self.data,description='x'*20000)).status_code,413)
        self.assertEqual(self.client.post('/api/complaints',data='{',content_type='application/json',headers=self.headers).status_code,400)

    def test_sql_payload_is_literal(self):
        title = "Example'); DROP TABLE complaints; --"
        receipt = self.post('/api/complaints',dict(self.data,title=title)).json
        result = self.post('/api/complaints/status',{k:receipt[k] for k in ['reference','access_token']})
        self.assertEqual(result.json['title'],title)
        self.assertEqual(self.post('/api/complaints/status',dict(reference="' OR 1=1 --",access_token='wrong')).status_code,404)
        self.assertEqual(self.post('/api/complaints',self.data).status_code,201)

    def test_request_boundaries(self):
        self.assertEqual(self.client.post('/api/complaints',json=self.data).status_code,403)
        self.assertEqual(self.client.post('/api/complaints',json=self.data,headers={**self.headers,'Origin':'https://other.test'}).status_code,403)
        self.assertEqual(self.client.post('/api/complaints',data='x',headers=self.headers).status_code,415)
        self.assertEqual(self.client.get('/',headers={'Host':'evil.test'}).status_code,400)

    def test_rate_limit_shared_and_forwarded_header_ignored(self):
        self.app.config['RATE_LIMIT'] = 2
        for _ in range(2):
            self.assertEqual(self.client.get('/api/health').status_code,200)
        response = self.client.get('/api/health',headers={'X-Forwarded-For':'1.2.3.4'})
        self.assertEqual(response.status_code,429)
        self.assertGreater(int(response.headers['Retry-After']),0)
        other = create_app({'TESTING':True,'DATABASE':self.database,'RATE_LIMIT':2}).test_client()
        self.assertEqual(other.get('/api/health').status_code,429)

    def test_document_search_download(self):
        self.assertEqual(len(self.client.get('/api/documents?q=privasi').json['items']),1)
        self.assertEqual(self.client.get('/api/documents?q='+'a'*101).status_code,400)
        self.assertEqual(self.client.get('/api/documents/panduan/download').status_code,200)
        self.assertEqual(self.client.get('/api/documents/unknown/download').status_code,404)
        self.assertEqual(self.client.get('/api/documents?q=%3Cscript%3E').json['items'],[])

if __name__ == '__main__':
    unittest.main()
