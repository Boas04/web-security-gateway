"""Explicit local Docker acceptance tests. Restores origin/settings/services in finally."""
import csv,io,json,time,unittest
from integration import ROOT,PUBLIC,ADMIN,compose
import requests

class FeatureIntegration(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  config=json.loads(compose('--profile','demo','config','--format','json'))
  if config['name']!='ruang-guard':raise RuntimeError('Wrong lab')
  cls.demo_was_running=bool(compose('--profile','demo','ps','-q','--status','running','demo-app').strip())
  if not cls.demo_was_running:compose('--profile','demo','up','-d','demo-app')
  cls.client=requests.Session();cls.client.trust_env=False
  csrf=cls.client.get(ADMIN+'session',timeout=5).json()['csrf']
  password=(ROOT/'secrets/initial-password.txt').read_text().strip()
  r=cls.client.post(ADMIN+'login',json={'password':password},headers={'X-CSRF-Token':csrf},timeout=10)
  if r.status_code!=200:raise RuntimeError('Local admin login failed')
  cls.csrf=r.json()['csrf'];cls.original=cls.client.get(ADMIN+'overview',timeout=5).json()['settings']
 @classmethod
 def post(cls,path,data):
  r=cls.client.post(ADMIN+path,json=data,headers={'X-CSRF-Token':cls.csrf},timeout=10);r.raise_for_status();return r
 @classmethod
 def change(cls,origin='ruang-warga',rate=120,window=60,duration=2):cls.post('settings',dict(origin=origin,rate=rate,window=window,duration=duration))
 @classmethod
 def clear(cls):
  state=cls.client.get(ADMIN+'overview',timeout=5).json()
  for client in {b['client'] for b in state['blocks']+state.get('offenses',[])}:cls.post('unblock',{'client':client})
 @classmethod
 def tearDownClass(cls):
  try:
   cls.clear();cls.change(**{k:cls.original[k] for k in ['origin','rate','window','duration']})
  finally:
   cls.post('logout',{});cls.client.close()
   if not cls.demo_was_running:compose('--profile','demo','stop','demo-app')
 def setUp(self):self.change();self.clear()
 def wait_for(self,predicate,seconds=75):
  deadline=time.monotonic()+seconds
  while time.monotonic()<deadline:
   try:
    response=self.client.get(ADMIN+'alerts',timeout=5)
   except (requests.ConnectionError,requests.Timeout):
    # Docker startup can briefly stall on the local host; retain the deadline.
    time.sleep(2);continue
   response.raise_for_status();state=response.json()
   if predicate(state):return state
   time.sleep(2)
  self.fail('Expected notification state not observed')
 def test_second_origin_and_private_portal_roundtrip(self):
  self.change(origin='katalog-lab')
  self.assertEqual(self.client.get(PUBLIC+'/api/health',timeout=10).json()['application'],'katalog-lab')
  self.assertIn('Katalog Lab',self.client.get(PUBLIC+'/',timeout=10).text)
  self.assertEqual(len(self.client.get(PUBLIC+'/api/items',timeout=10).json()['items']),6)
  self.assertEqual(self.client.get(PUBLIC+'/api/items',params={'q':'<script>alert(1)</script>'},timeout=10).status_code,403)
  time.sleep(2.2);self.assertEqual(self.client.get(PUBLIC+'/api/health',timeout=10).status_code,200)
  config=json.loads(compose('--profile','demo','config','--format','json'))
  self.assertFalse(config['services']['demo-app'].get('ports'))
  published=json.loads(compose('--profile','demo','ps','--format','json','demo-app').strip());published=published[0] if isinstance(published,list) else published
  self.assertFalse(any(p.get('PublishedPort',0) for p in published.get('Publishers') or []))
  deadline=time.monotonic()+30
  while time.monotonic()<deadline:
   health=self.client.get(ADMIN+'overview',timeout=5).json()['health']
   if health and health[0]['origin']=='katalog-lab' and health[0]['available']:break
   time.sleep(2)
  else:self.fail('Second origin monitor did not report availability')
  self.change();self.clear()
  body={'title':'Lampu taman pengujian','category':'Lingkungan','location':'Kota Imaji','description':'Lampu taman fiktif diperiksa dalam pengujian integrasi lokal.'}
  headers={'Origin':PUBLIC,'X-Lab-Request':'1'}
  r=self.client.post(PUBLIC+'/api/complaints',json=body,headers=headers,timeout=10);self.assertEqual(r.status_code,201)
  receipt=r.json();lookup={k:receipt[k] for k in ['reference','access_token']}
  self.assertEqual(self.client.post(PUBLIC+'/api/complaints/status',json=lookup,headers=headers,timeout=10).status_code,200)
  lookup['access_token']='wrong';self.assertEqual(self.client.post(PUBLIC+'/api/complaints/status',json=lookup,headers=headers,timeout=10).status_code,404)
  report=self.client.get(ADMIN+'reports?range=7d&format=json',timeout=10)
  self.assertEqual(report.status_code,200);self.assertNotIn(receipt['access_token'],report.text);self.assertNotIn(body['description'],report.text)
 def test_notifications_failures_dedupe_and_recovery(self):
  for service,kind,target in [('portal','origin_unavailable','ruang-warga'),('waf','waf_unavailable','waf')]:
   try:
    compose('stop',service)
    find=lambda s:next((a for a in s['alerts'] if a['kind']==kind and a['target']==target and a['resolved_at'] is None),None)
    state=self.wait_for(find);item=find(state)
    time.sleep(17);current=find(self.client.get(ADMIN+'alerts',timeout=5).json());self.assertEqual(current['id'],item['id'])
    self.assertEqual(self.client.post(ADMIN+'alerts/ack',json={'id':item['id']},timeout=5).status_code,403)
    self.post('alerts/ack',{'id':item['id']})
   finally:compose('start',service)
   self.wait_for(lambda s:any(a['id']==item['id'] and a['resolved_at'] is not None and a['resolution']=='recovered' for a in s['alerts']))
 def test_spike_exports_and_cleanup_expiry(self):
  policy=self.client.get(ADMIN+'alerts',timeout=5).json()['policy'];self.assertLessEqual(policy['threshold'],100,'Lab test bound')
  self.change(rate=2,duration=20)
  for _ in range(policy['threshold']+3):self.client.get(PUBLIC+'/api/health',timeout=10)
  self.wait_for(lambda s:any(a['kind']=='blocked_spike' and a['resolved_at'] is None for a in s['alerts']))
  # Forces cleanup after expiry; a full counter must not reblock inside window.
  time.sleep(21)
  compose('exec','-T','monitor','python','-c','from guard.core import load_store; load_store().cleanup()')
  self.assertEqual(self.client.get(PUBLIC+'/api/health',timeout=10).status_code,200)
  self.wait_for(lambda s:not any(a['kind']=='blocked_spike' and a['resolved_at'] is None for a in s['alerts']),seconds=90)
  report=self.client.get(ADMIN+'reports?range=7d&format=json',timeout=10);self.assertEqual(report.status_code,200);data=report.json();self.assertEqual(len(data['events']),data['totals']['total']);self.assertIn('latency_ms',data);self.assertTrue(data['incidents']);self.assertTrue(data['health'])
  csv_response=self.client.get(ADMIN+'reports?range=7d&format=csv',timeout=10);self.assertEqual(csv_response.status_code,200);self.assertGreater(len(list(csv.reader(io.StringIO(csv_response.text)))),1)
if __name__=='__main__':unittest.main(verbosity=2)
