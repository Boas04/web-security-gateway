"""Run explicitly against this local Docker lab; never against arbitrary URLs.
Temporarily stops portal and WAF and restores them in finally blocks.
"""
import json
from pathlib import Path
import subprocess
import time
import unittest
import requests

ROOT=Path(__file__).resolve().parents[1]
PUBLIC='http://localhost:8090'
ADMIN='http://localhost:9000/admin/api/'

def compose(*args):
    return subprocess.run(['docker','compose',*args],cwd=ROOT,check=True,capture_output=True,text=True).stdout

class DockerIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config=json.loads(compose('config','--format','json'))
        if config['name']!='ruang-guard': raise RuntimeError('Only named ruang-guard lab is supported')
        cls.http=requests.Session(); cls.http.trust_env=False
        cls.admin=requests.Session(); cls.admin.trust_env=False
        session=cls.admin.get(ADMIN+'session',timeout=5).json()
        password=(ROOT/'secrets/initial-password.txt').read_text().strip()
        result=cls.admin.post(ADMIN+'login',json={'password':password},headers={'X-CSRF-Token':session['csrf']},timeout=5)
        if result.status_code!=200: raise RuntimeError('Admin login failed')
        cls.csrf=result.json()['csrf']
        cls.original=cls.admin.get(ADMIN+'overview',timeout=5).json()['settings']

    @classmethod
    def change(cls, rate=120,window=60,duration=2):
        result=cls.admin.post(ADMIN+'settings',json=dict(origin=cls.original['origin'],rate=rate,window=window,duration=duration),headers={'X-CSRF-Token':cls.csrf},timeout=5)
        if result.status_code!=200: raise RuntimeError('Settings update failed')

    @classmethod
    def clear_blocks(cls):
        overview=cls.admin.get(ADMIN+'overview',timeout=5).json()
        for block in {b['client']:b for b in overview['blocks']+overview.get('offenses',[])}.values():
            cls.admin.post(ADMIN+'unblock',json={'client':block['client']},headers={'X-CSRF-Token':cls.csrf},timeout=5).raise_for_status()

    def setUp(self): self.change(); self.clear_blocks()

    def wait_for_restored_gateway(self):
        # Container "running" is not application readiness on a busy Docker host.
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            try:
                response=self.http.get(PUBLIC+'/api/health',timeout=5)
                if response.status_code==200 and response.json().get('environment')=='fictional-local-lab':return
            except (requests.ConnectionError,requests.Timeout):
                pass
            time.sleep(1)
        self.fail('Lab gateway did not recover after service restart')

    @classmethod
    def tearDownClass(cls):
        cls.clear_blocks()
        cls.change(cls.original['rate'],cls.original['window'],cls.original['duration'])
        cls.admin.post(ADMIN+'logout',json={},headers={'X-CSRF-Token':cls.csrf},timeout=5)
        cls.admin.close(); cls.http.close()

    def test_normal_complaint_roundtrip(self):
        self.assertEqual(self.http.get(PUBLIC+'/',timeout=10).status_code,200)
        body=dict(title='Lampu taman rekaan',category='Lingkungan',location='Kota Imaji',description='Lampu di taman rekaan tidak menyala dalam simulasi malam ini.')
        headers={'X-Lab-Request':'1','Origin':PUBLIC}
        response=self.http.post(PUBLIC+'/api/complaints',json=body,headers=headers,timeout=10)
        self.assertEqual(response.status_code,201)
        receipt=response.json()
        lookup={key:receipt[key] for key in ['reference','access_token']}
        response=self.http.post(PUBLIC+'/api/complaints/status',json=lookup,headers=headers,timeout=10)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['title'],body['title'])
        lookup['access_token']='wrong'
        self.assertEqual(self.http.post(PUBLIC+'/api/complaints/status',json=lookup,headers=headers,timeout=10).status_code,404)
        logs=self.admin.get(ADMIN+'overview',timeout=5).text
        self.assertNotIn(receipt['access_token'],logs)
        self.assertNotIn(body['description'],logs)

    def test_real_waf_rule_and_block_expiry(self):
        result=self.http.get(PUBLIC+'/api/documents',params={'q':'<script>alert(1)</script>'},timeout=10)
        self.assertEqual(result.status_code,403)
        events=self.admin.get(ADMIN+'overview',timeout=5).json()['events']
        self.assertTrue(any(e['reason']=='waf_rule' and any(941000<=r<942000 for r in e['rules']) for e in events))
        self.assertEqual(self.http.get(PUBLIC+'/api/health',timeout=10).status_code,429)
        time.sleep(2.2)
        self.assertEqual(self.http.get(PUBLIC+'/api/health',timeout=10).status_code,200)

    def test_rate_and_manual_unblock(self):
        self.change(rate=2)
        for _ in range(2):self.assertEqual(self.http.get(PUBLIC+'/api/health',timeout=10).status_code,200)
        result=self.http.get(PUBLIC+'/api/health',headers={'X-Forwarded-For':'192.0.2.77'},timeout=10)
        self.assertEqual(result.status_code,429)
        self.assertIn('Retry-After',result.headers)
        self.clear_blocks()
        self.assertEqual(self.http.get(PUBLIC+'/api/health',timeout=10).status_code,200)

    def test_dashboard_auth_and_no_direct_bypass(self):
        self.assertEqual(requests.get(ADMIN+'overview',timeout=5).status_code,401)
        self.assertEqual(self.admin.post(ADMIN+'settings',json={},timeout=5).status_code,403)
        self.assertEqual(self.http.get(PUBLIC+'/admin/api/overview',timeout=10).status_code,404)
        config=json.loads(compose('config','--format','json'))
        for service in ['portal','waf','monitor']:self.assertFalse(config['services'][service].get('ports'))
        for service in ['gateway','admin']:
            self.assertTrue(all(p['host_ip']=='127.0.0.1' for p in config['services'][service]['ports']))
        gateway_ports=config['services']['gateway']['ports']
        self.assertEqual(len(gateway_ports),1)
        self.assertEqual(str(gateway_ports[0]['published']),'8090')
        self.assertEqual(gateway_ports[0]['target'],8080)
        inspect=json.loads(compose('ps','--format','json','portal').strip())
        if isinstance(inspect,list): inspect=inspect[0]
        # Current Compose prints one JSON object per service; published ports must be absent.
        self.assertFalse(any(p.get('PublishedPort',0) for p in (inspect.get('Publishers') or [])))
        isolated=compose('exec','-T','admin','python','-c',"import socket; s=socket.socket(); s.settimeout(3); print('isolated' if s.connect_ex(('172.30.10.10',8000)) else 'reachable'); s.close()")
        self.assertEqual(isolated.strip(),'isolated')

    def test_origin_unavailable_and_monitor(self):
        try:
            compose('stop','portal')
            self.assertEqual(self.http.get(PUBLIC+'/api/health',timeout=15).status_code,502)
            deadline=time.monotonic()+25
            while time.monotonic()<deadline:
                health=self.admin.get(ADMIN+'overview',timeout=5).json()['health']
                if health and health[0]['available']==0:break
                time.sleep(1)
            else:self.fail('Monitor did not report origin outage')
        finally:
            compose('start','portal')
            self.wait_for_restored_gateway()

    def test_waf_unavailable_is_fail_closed(self):
        try:
            compose('stop','waf')
            self.assertEqual(self.http.get(PUBLIC+'/api/health',timeout=15).status_code,503)
        finally:
            compose('start','waf')
            self.wait_for_restored_gateway()

if __name__=='__main__': unittest.main(verbosity=2)
