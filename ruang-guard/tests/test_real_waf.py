"""Optional composed test: real Coraza HTTP service + gateway + real portal WSGI.
Origin transport stays in-process; Docker network isolation is checked separately.
Set WAF_TEST_URL=http://127.0.0.1:18081/inspect after starting the built inspector.
"""
import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import requests
from guard.core import Store
from guard.gateway import create_app
from test_guard import portal, PortalTransport

@unittest.skipUnless(os.getenv('WAF_TEST_URL'), 'Real inspector not running; run Go tests or Docker integration.')
class RealWAFIntegration(unittest.TestCase):
    def setUp(self):
        self.url=os.environ['WAF_TEST_URL']
        if self.url!='http://127.0.0.1:18081/inspect': raise ValueError('Only dedicated loopback test inspector allowed')
        self.tmp=tempfile.TemporaryDirectory()
        self.store=Store(Path(self.tmp.name)/'guard.db','s'*48,{'lab':dict(address='172.30.10.10',port=8000,health_path='/api/health')})
        origin=portal.create_app({'TESTING':True,'DATABASE':self.tmp.name+'/portal.db','RATE_LIMIT':10000}).test_client()
        class CombinedTransport(PortalTransport):
            def post(self, url, **kwargs):
                with requests.Session() as session:
                    session.trust_env=False
                    return session.post(url,**kwargs)
        self.transport=CombinedTransport(origin)
        with patch.dict(os.environ,{'WAF_URL':self.url}):
            self.client=create_app(self.store,lambda:self.transport).test_client()
        self.headers={'User-Agent':'RuangGuardLab/1.0','Accept':'application/json','X-Lab-Request':'1','Origin':'http://localhost:8090'}

    def tearDown(self):self.tmp.cleanup()

    def test_actual_complaint_and_lookup(self):
        body=dict(title='Lampu taman rekaan',category='Lingkungan',location='Kota Imaji',description='Lampu di taman rekaan tidak menyala dalam simulasi malam ini.')
        result=self.client.post('/api/complaints',json=body,headers=self.headers)
        self.assertEqual(result.status_code,201,self.store.snapshot()['events'])
        lookup={k:result.json[k] for k in ('reference','access_token')}
        result=self.client.post('/api/complaints/status',json=lookup,headers=self.headers)
        self.assertEqual(result.status_code,200,self.store.snapshot()['events'])
        self.assertEqual(result.json['title'],body['title'])

    def test_actual_xss_never_reaches_origin(self):
        result=self.client.get('/api/documents?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E',headers=self.headers)
        self.assertEqual(result.status_code,403)
        self.assertEqual(len(self.transport.seen),0)
        self.assertTrue(any(941000<=i<942000 for i in self.store.snapshot()['events'][0]['rules']))

    def test_actual_sql_never_reaches_origin(self):
        result=self.client.get('/api/documents?q=1%27%20OR%20%271%27%3D%271%27%20--',headers=self.headers)
        self.assertEqual(result.status_code,403)
        self.assertEqual(len(self.transport.seen),0)
        self.assertTrue(any(942000<=i<943000 for i in self.store.snapshot()['events'][0]['rules']))

    def test_actual_json_xss_and_redacted_verdict(self):
        result=self.client.post('/api/complaints',json={'description':'<script>alert(1)</script> PRIVATE_SENTINEL'},headers=self.headers)
        self.assertEqual(result.status_code,403)
        self.assertNotIn('PRIVATE_SENTINEL',str(self.store.snapshot()))

    def test_actual_path_traversal_never_reaches_origin(self):
        result=self.client.get('/api/documents?file=..%2F..%2F..%2F..%2Ffictional-secret.txt',headers=self.headers)
        self.assertEqual(result.status_code,403)
        self.assertEqual(len(self.transport.seen),0)
        self.assertTrue(any(930000<=i<931000 for i in self.store.snapshot()['events'][0]['rules']))
