import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import Mock, patch

import requests
from werkzeug.security import generate_password_hash
from guard.core import Store, check_health, validate_origins
from guard.gateway import create_app as gateway_app
from guard.admin import create_app as admin_app

PORTAL_PATH = Path(__file__).resolve().parents[2] / 'ruang-warga' / 'app.py'
spec = importlib.util.spec_from_file_location('portal', PORTAL_PATH)
portal = importlib.util.module_from_spec(spec)
sys.modules['portal'] = portal
spec.loader.exec_module(portal)


class PortalTransport:
    """HTTP transport adapter using the actual Ruang Warga Flask application."""
    def __init__(self, client):
        self.client, self.seen = client, []
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def send(self, request, **kwargs):
        self.seen.append(request)
        result = self.client.open(request.path_url, method=request.method, headers=dict(request.headers), data=request.body)
        response = requests.Response()
        response.status_code = result.status_code
        response.headers.update(result.headers)
        response._content = result.data
        response._content_consumed = True
        return response


class GuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = generate_password_hash('test-only-random-password', method='scrypt')

    def setUp(self):
        environment = patch.dict(os.environ, {'PUBLIC_ORIGIN':'http://localhost:8090'})
        environment.start()
        self.addCleanup(environment.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.now = 1000.
        self.store = Store(Path(self.tmp.name)/'guard.db','x'*48,{'ruang-warga':{'address':'172.30.10.10','port':8000,'health_path':'/api/health'}},now=lambda:self.now)
        self.admin = admin_app(self.store,self.password_hash).test_client()
        self.portal = portal.create_app({'TESTING':True,'DATABASE':self.tmp.name+'/portal.db','RATE_LIMIT':10000}).test_client()
        self.transport = PortalTransport(self.portal)
        # Policy/proxy unit tests inject a verdict. Actual CRS tests live in waf/main_test.go.
        self.inspect = Mock(return_value={'allowed':True,'rules':[]})
        self.gateway = gateway_app(self.store,lambda:self.transport,self.inspect).test_client()

    def tearDown(self): self.tmp.cleanup()

    def login(self):
        self.csrf = self.admin.get('/admin/api/session').json['csrf']
        response = self.admin.post('/admin/api/login',json={'password':'test-only-random-password'},headers={'X-CSRF-Token':self.csrf})
        self.assertEqual(response.status_code,200)
        self.csrf = response.json['csrf']

    def post(self,path,data):
        return self.admin.post('/admin/api/'+path,json=data,headers={'X-CSRF-Token':self.csrf})

    def test_public_failure_messages_and_private_reasons(self):
        self.inspect.side_effect = requests.ConnectionError('private diagnostic')
        response = self.gateway.get('/api/health')
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json['code'], 'service_unavailable')
        self.assertIn('Layanan sementara tidak tersedia', response.json['error'])
        self.assertNotIn('WAF', response.text)
        self.assertNotIn('private diagnostic', response.text)
        self.assertEqual(self.store.snapshot()['events'][0]['reason'], 'waf_unavailable')
        page = self.gateway.get('/', headers={'Accept':'text/html'})
        self.assertEqual(page.mimetype, 'text/html')
        self.assertIn('Layanan sementara tidak tersedia', page.text)
        self.assertIn("default-src 'none'", page.headers['Content-Security-Policy'])
        self.assertEqual(self.gateway.get('/api/health', headers={'Accept':'text/html'}).mimetype, 'application/json')
        self.inspect.side_effect = None
        with patch.object(self.transport, 'send', side_effect=requests.ConnectionError('private origin')):
            response = self.gateway.get('/api/health')
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json['code'], 'service_unavailable')
        self.assertEqual(self.store.snapshot()['events'][0]['reason'], 'origin_unavailable')

    def test_public_rejection_and_actual_retry_time(self):
        self.inspect.return_value = {'allowed':False, 'rules':[941100]}
        response = self.gateway.get('/api/health')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json['code'], 'security_restriction')
        self.assertNotIn('941100', response.text)
        self.now += 3
        response = self.gateway.get('/api/health')
        self.assertEqual(response.status_code, 429)
        retry = int(response.headers['Retry-After'])
        self.assertGreater(retry, 0)
        self.assertIn(f'{retry} detik', response.json['error'])
        self.assertEqual(response.json['code'], 'too_many_requests')
        self.assertEqual(self.store.snapshot()['events'][0]['reason'], 'waf_rule')

    def test_normal_complaint_and_private_lookup(self):
        payload = dict(title='Lampu taman fiktif',category='Lingkungan',location='Kota Imaji',description='Lampu di taman rekaan tidak menyala dalam simulasi malam hari.')
        response = self.gateway.post('/api/complaints',json=payload,headers={'X-Lab-Request':'1','Origin':'http://localhost:8090'})
        self.assertEqual(response.status_code,201)
        lookup = {key:response.json[key] for key in ['reference','access_token']}
        result = self.gateway.post('/api/complaints/status',json=lookup,headers={'X-Lab-Request':'1'})
        self.assertEqual(result.json['title'],payload['title'])
        lookup['access_token']='wrong'
        self.assertEqual(self.gateway.post('/api/complaints/status',json=lookup,headers={'X-Lab-Request':'1'}).status_code,404)
        serialized = json.dumps(self.store.snapshot())
        self.assertNotIn(response.json['access_token'],serialized)
        self.assertNotIn(payload['description'],serialized)
        self.assertTrue(all(e['origin']=='ruang-warga' for e in self.store.snapshot()['events']))

    def test_public_origin_configuration_is_strict(self):
        for value in ['http://localhost:8090','http://127.0.0.1:8090']:
            with self.subTest(value=value), patch.dict(os.environ, {'PUBLIC_ORIGIN':value}):
                gateway_app(self.store,lambda:self.transport,self.inspect)
        for value in ['http://localhost:8080','http://127.0.0.1:8080','http://0.0.0.0:8090','http://evil.test:8090','https://localhost:8090','http://localhost:8090/','http://localhost:8090/path','http://user@localhost:8090']:
            with self.subTest(value=value), patch.dict(os.environ, {'PUBLIC_ORIGIN':value}):
                with self.assertRaises(ValueError):
                    gateway_app(self.store,lambda:self.transport,self.inspect)

    def test_8090_aliases_preserve_canonical_headers_and_origin_port(self):
        payload=dict(title='Lampu taman fiktif',category='Lingkungan',location='Kota Imaji',description='Lampu taman rekaan tidak menyala dalam simulasi malam ini.')
        for canonical in ['http://localhost:8090','http://127.0.0.1:8090']:
            with patch.dict(os.environ, {'PUBLIC_ORIGIN':canonical}):
                client=gateway_app(self.store,lambda:self.transport,self.inspect).test_client()
            for incoming in ['http://localhost:8090','http://127.0.0.1:8090']:
                with self.subTest(canonical=canonical,incoming=incoming):
                    response=client.post('/api/complaints',json=payload,headers={'Origin':incoming,'Host':incoming.split('://')[1],'X-Lab-Request':'1'})
                    self.assertEqual(response.status_code,201)
                    forwarded=self.transport.seen[-1]
                    self.assertEqual(forwarded.url,'http://172.30.10.10:8000/api/complaints')
                    self.assertEqual(forwarded.headers['Host'],canonical.split('://')[1])
                    self.assertEqual(forwarded.headers['Origin'],canonical)

    def test_old_or_foreign_origin_is_rejected_before_forwarding(self):
        for origin in ['http://localhost:8080','http://127.0.0.1:8080','http://localhost:9000','http://evil.test:8090','null']:
            with self.subTest(origin=origin):
                self.assertEqual(self.gateway.post('/api/complaints',json={},headers={'Origin':origin}).status_code,403)
        self.assertEqual(len(self.transport.seen),0)
        self.inspect.assert_not_called()

    def test_trusted_hosts_remain_loopback_only(self):
        for host in ['evil.test:8090','localhost.evil.test:8090','172.30.10.10:8000']:
            with self.subTest(host=host):
                self.assertEqual(self.gateway.get('/api/health',headers={'Host':host}).status_code,400)
        self.assertEqual(len(self.transport.seen),0)

    def test_health_check_uses_8090_host_and_internal_8000(self):
        client=Mock()
        client.__enter__=Mock(return_value=client)
        client.__exit__=Mock(return_value=False)
        response=Mock(status_code=200)
        response.__enter__=Mock(return_value=response)
        response.__exit__=Mock(return_value=False)
        client.get.return_value=response
        check_health(self.store,session_factory=lambda:client)
        client.get.assert_called_once_with('http://172.30.10.10:8000/api/health',headers={'Host':'localhost:8090'},timeout=(2,3),allow_redirects=False,stream=True)
        self.assertEqual(self.store.snapshot()['health'][0]['available'],1)

    def test_waf_verdict_blocks_before_origin_and_expires(self):
        self.inspect.return_value={'allowed':False,'rules':[941100,949110]}
        result = self.gateway.get('/api/documents?q=private-secret')
        self.assertEqual(result.status_code,403)
        self.assertEqual(len(self.transport.seen),0)
        self.assertEqual(self.gateway.get('/').status_code,429)
        event = self.store.snapshot()['events'][-1]
        self.assertEqual(event['rules'],[941100,949110])
        self.assertNotIn('private-secret',json.dumps(self.store.snapshot()))
        self.now+=self.store.settings()['duration']+1
        self.inspect.return_value={'allowed':True,'rules':[]}
        self.assertEqual(self.gateway.get('/').status_code,200)

    def test_rate_limit_forwarded_headers_and_admin_unblock(self):
        self.store.update('ruang-warga',2,60,30)
        for i in range(2): self.assertEqual(self.gateway.get('/api/health',headers={'X-Forwarded-For':f'10.0.0.{i}'}).status_code,200)
        response=self.gateway.get('/api/health',headers={'X-Forwarded-For':'8.8.8.8'})
        self.assertEqual(response.status_code,429)
        self.assertEqual(response.headers['Retry-After'],'30')
        self.assertNotIn('X-Forwarded-For',self.transport.seen[0].headers)
        other=Store(self.store.path,self.store.secret,self.store.origins,now=lambda:self.now)
        self.assertGreater(other.limit(other.identity('127.0.0.1'))[0],0)
        self.login()
        self.assertEqual(self.post('unblock',{'client':self.store.identity('127.0.0.1')}).status_code,200)
        self.assertEqual(self.gateway.get('/api/health').status_code,200)

    def test_admin_auth_csrf_rotation_logout_expiry(self):
        self.assertEqual(self.admin.get('/admin/api/overview').status_code,401)
        old=self.admin.get('/admin/api/session').json['csrf']
        self.assertEqual(self.admin.post('/admin/api/login',json={'password':'test-only-random-password'}).status_code,403)
        self.login()
        self.assertNotEqual(old,self.csrf)
        self.assertEqual(self.admin.post('/admin/api/logout',json={},headers={'X-CSRF-Token':old}).status_code,403)
        self.assertEqual(self.admin.post('/admin/api/logout',json={},headers={'X-CSRF-Token':self.csrf,'Origin':'http://evil.test'}).status_code,403)
        self.assertEqual(self.admin.get('/admin/api/overview').status_code,200)
        self.now+=3601
        self.assertEqual(self.admin.get('/admin/api/overview').status_code,401)
        self.login()
        self.assertEqual(self.post('logout',{}).status_code,200)
        self.assertEqual(self.admin.get('/admin/api/overview').status_code,401)

    def test_admin_login_rate_limit(self):
        csrf=self.admin.get('/admin/api/session').json['csrf']
        for _ in range(5):
            self.assertEqual(self.admin.post('/admin/api/login',json={'password':'wrong'},headers={'X-CSRF-Token':csrf}).status_code,401)
        result=self.admin.post('/admin/api/login',json={'password':'wrong'},headers={'X-CSRF-Token':csrf})
        self.assertEqual(result.status_code,429)

    def test_settings_are_admin_only_and_origin_not_a_url(self):
        self.csrf=self.admin.get('/admin/api/session').json['csrf']
        data=dict(origin='ruang-warga',rate=10,window=30,duration=60)
        self.assertEqual(self.post('settings',data).status_code,401)
        self.login()
        self.assertEqual(self.post('settings',dict(data,origin='http://169.254.169.254')).status_code,400)
        self.assertEqual(self.post('settings',dict(data,rate=True)).status_code,400)
        self.assertEqual(self.post('settings',data).status_code,200)
        for address in ['169.254.169.254','127.0.0.1','8.8.8.8','example.com','::1']:
            with self.assertRaises(ValueError): validate_origins({'test':dict(address=address,port=80,health_path='/')})

    def test_unavailable_waf_is_fail_closed(self):
        self.inspect.side_effect=requests.ConnectionError('sensitive URL must not be logged')
        self.assertEqual(self.gateway.get('/').status_code,503)
        self.assertEqual(len(self.transport.seen),0)
        self.assertNotIn('sensitive',json.dumps(self.store.snapshot()))

    def test_unavailable_origin_and_health(self):
        broken=Mock()
        broken.__enter__=Mock(return_value=broken)
        broken.__exit__=Mock(return_value=False)
        broken.send.side_effect=requests.ConnectionError()
        broken.get.side_effect=requests.ConnectionError()
        gateway=gateway_app(self.store,lambda:broken,self.inspect).test_client()
        self.assertEqual(gateway.get('/').status_code,502)
        check_health(self.store,session_factory=lambda:broken)
        self.assertEqual(self.store.snapshot()['health'][0]['available'],0)

    def test_gateway_limits_and_no_admin_cookie_forwarding(self):
        self.assertEqual(self.gateway.post('/api/complaints',data='x'*17000).status_code,413)
        self.assertEqual(self.gateway.get('/admin/api/overview').status_code,404)
        self.assertEqual(self.gateway.post('/api/complaints',data='compressed',headers={'Content-Encoding':'gzip'}).status_code,415)
        self.assertEqual(self.gateway.post('/api/complaints',json={},headers={'Origin':'http://evil.test'}).status_code,403)
        self.gateway.set_cookie('rg_session','must-not-leak')
        self.gateway.get('/')
        self.assertNotIn('must-not-leak',self.transport.seen[-1].headers.get('Cookie',''))

    def test_redaction_unknown_paths_and_retention(self):
        self.gateway.get('/secret-access-token?password=hidden')
        snapshot=json.dumps(self.store.snapshot())
        self.assertNotIn('secret-access-token',snapshot)
        self.assertNotIn('password',snapshot)
        self.now+=8*86400
        self.store.cleanup()
        self.assertEqual(self.store.snapshot()['totals']['total'],0)

if __name__=='__main__': unittest.main()
