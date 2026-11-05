import csv,io,tempfile,unittest,importlib.util
from pathlib import Path
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from guard.core import Store
from guard.admin import create_app
from guard import alerts
class Features(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.now=10000
  self.store=Store(Path(self.tmp.name)/'db','test-key'*8,{'one':{'address':'172.30.10.10','port':8000,'health_path':'/api/health'},'two':{'address':'172.30.10.20','port':8000,'health_path':'/api/health'}},now=lambda:self.now)
  self.client=create_app(self.store,generate_password_hash('test-only',method='scrypt')).test_client()
  p=patch.dict('os.environ',{'ALERT_BLOCK_THRESHOLD':'3','ALERT_WINDOW_SECONDS':'60','ALERT_FAILURE_COUNT':'2'});p.start();self.addCleanup(p.stop)
 def login(self):
  csrf=self.client.get('/admin/api/session').json['csrf'];r=self.client.post('/admin/api/login',json={'password':'test-only'},headers={'X-CSRF-Token':csrf});self.assertEqual(r.status_code,200);self.csrf=r.json['csrf']
 def tick(self,healthy=True,waf=True):
  self.now+=15
  with self.store.db() as db:db.execute('INSERT INTO health(at,origin,available,status,ms) VALUES(?,?,?,?,?)',(self.now,self.store.settings()['origin'],healthy,200 if healthy else 0,1))
  alerts.evaluate(self.store,waf)
 def test_dedupe_ack_recovery_recurrence(self):
  self.tick(False,False);self.assertEqual(alerts.snapshot(self.store)['active_count'],0)
  self.tick(False,False);state=alerts.snapshot(self.store);self.assertEqual(state['active_count'],2);ids=[x['id'] for x in state['alerts']]
  self.tick(False,False);self.assertEqual([x['id'] for x in alerts.snapshot(self.store)['alerts']],ids)
  self.assertTrue(alerts.acknowledge(self.store,ids[0]));self.assertEqual(alerts.snapshot(self.store)['active_count'],2)
  self.tick();self.assertEqual(alerts.snapshot(self.store)['active_count'],0)
  self.tick(False,False);self.tick(False,False);self.assertEqual(len(alerts.snapshot(self.store)['alerts']),4)
 def test_threshold_expiry_monitor_and_origin_switch(self):
  for _ in range(3):self.store.event('masked','GET','/api/health',429,'blocked','rate_limit',[],1)
  self.tick();self.assertEqual(alerts.snapshot(self.store)['active_count'],1)
  self.now+=61;self.assertTrue(alerts.snapshot(self.store)['monitor']['stale']);self.tick();self.assertEqual(alerts.snapshot(self.store)['active_count'],0)
  self.tick(False);self.tick(False);self.store.update('two',120,60,60);self.tick();self.assertEqual(alerts.snapshot(self.store)['alerts'][0]['resolution'],'origin_changed')
 def test_auth_csrf_and_readonly(self):
  for path in ['alerts','reports']:self.assertEqual(self.client.get('/admin/api/'+path).status_code,401)
  self.login();self.tick(False);self.tick(False);identifier=alerts.snapshot(self.store)['alerts'][0]['id']
  self.assertEqual(self.client.post('/admin/api/alerts/ack',json={'id':identifier}).status_code,403)
  self.assertEqual(self.client.post('/admin/api/alerts/ack',json={'id':True},headers={'X-CSRF-Token':self.csrf}).status_code,400)
  self.assertEqual(self.client.post('/admin/api/alerts/ack',json={'id':identifier},headers={'X-CSRF-Token':self.csrf}).status_code,200)
  with self.store.db() as db:before=list(db.iterdump())
  self.client.get('/admin/api/alerts')
  with self.store.db() as db:self.assertEqual(before,list(db.iterdump()))
 def test_report_filter_allrows_latency_csv_privacy(self):
  self.login()
  for i in range(125):self.store.event('=formula','GET','/api/health',200,'allowed','forwarded',[],i)
  self.tick();r=self.client.get('/admin/api/reports?format=json&q=forwarded');self.assertEqual(r.status_code,200);self.assertEqual(len(r.json['events']),125);self.assertEqual(r.json['latency_ms']['p95'],118);self.assertEqual(len(r.json['health']),1)
  self.assertIn('attachment',r.headers['Content-Disposition']);self.assertNotIn('test-only',r.text);self.assertNotIn('test-key',r.text)
  rows=list(csv.reader(io.StringIO(self.client.get('/admin/api/reports?format=csv').text)));self.assertEqual(len(rows),126);self.assertEqual(rows[1][2],"'=formula")
  self.assertEqual(self.client.get('/admin/api/reports?q=absent').json['totals']['total'],0)
  for query in ['format=html','format=json&x=1','q='+('a'*201)]:self.assertEqual(self.client.get('/admin/api/reports?'+query).status_code,400)
 def test_demo_query_and_escape(self):
  spec=importlib.util.spec_from_file_location('catalog',Path(__file__).resolve().parents[1]/'demo-app/app.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);c=m.create_app().test_client()
  self.assertEqual(c.get('/api/health').json['application'],'katalog-lab');self.assertEqual(len(c.get('/api/items').json['items']),6)
  self.assertEqual(c.get('/api/items',query_string={'q':"' OR 1=1 --"}).json['items'],[])
  response=c.get('/',query_string={'q':'<script>'});self.assertEqual(response.status_code,200);self.assertNotIn('<script>',response.text);self.assertIn('&lt;script&gt;',response.text)
  self.assertEqual(c.get('/api/items?q='+('x'*101)).status_code,400);self.assertEqual(c.get('/',headers={'Host':'evil.test'}).status_code,400)

 def test_waf_probe_fails_closed_without_raw_data(self):
  from unittest.mock import MagicMock
  import requests
  factory=MagicMock();response=factory.return_value.__enter__.return_value.post.return_value.__enter__.return_value
  response.status_code=200;response.json.return_value={'allowed':True,'rules':[]}
  self.assertTrue(alerts.check_waf(factory))
  call=factory.return_value.__enter__.return_value.post.call_args
  self.assertEqual(call.args[0],'http://waf:8081/inspect');self.assertFalse(call.kwargs['allow_redirects'])
  response.json.return_value={'allowed':False,'rules':[]};self.assertFalse(alerts.check_waf(factory))
  factory.return_value.__enter__.return_value.post.side_effect=requests.ConnectionError('sensitive-marker')
  self.assertFalse(alerts.check_waf(factory))
