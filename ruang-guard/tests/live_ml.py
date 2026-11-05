"""Live controlled-local-traffic ML acceptance. About 9 minutes, no synthetic DB inserts.
Six disposable clients on this compose network send only fictional normal traffic.
Their real source-minute events are approved as lab baseline; training/activation use admin API.
"""
import concurrent.futures,json,math,secrets,subprocess,time
from pathlib import Path
import requests
from integration import ROOT,ADMIN,PUBLIC,compose

CLIENT_SOURCE=r"""
import json,math,socket,time,requests
from requests.adapters import HTTPAdapter
from guard.core import load_store
class Bound(HTTPAdapter):
 def init_poolmanager(self,*args,**kwargs):kwargs['source_address']=(local,0);return super().init_poolmanager(*args,**kwargs)
store=load_store()
with socket.create_connection(('gateway',8080),timeout=10) as sock:local=sock.getsockname()[0];target=sock.getpeername()[0]
client_id=store.identity(local)
with requests.Session() as client:
 client.trust_env=False;client.mount('http://',Bound())
 client.headers.update({'Host':'localhost:8090','User-Agent':'RuangGuardControlledLab/1.0','Origin':'http://localhost:8090','X-Lab-Request':'1'})
 latencies=[];windows=[]
 for minute in range(7):
  at=START+minute*60+2+ACTOR
  while time.time()<at:time.sleep(min(1,at-time.time()))
  started=time.time();count=5+(minute+ACTOR)%9
  for n in range(count):
   path=['/api/health','/api/categories','/api/documents'][n%3]
   begin=time.monotonic();r=client.get('http://'+target+':8080'+path,timeout=10)
   if r.status_code!=200:raise RuntimeError('Normal request failed: '+str(r.status_code))
   latencies.append((time.monotonic()-begin)*1000)
  body=dict(title='Lampu taman baseline fiktif',category='Lingkungan',location='Kota Imaji',description='Pengaduan fiktif untuk pengujian alur layanan normal pada lab lokal.')
  r=client.post('http://'+target+':8080/api/complaints',json=body,timeout=10)
  if r.status_code!=201:raise RuntimeError('Complaint baseline failed')
  receipt=r.json();r=client.post('http://'+target+':8080/api/complaints/status',json={k:receipt[k] for k in ['reference','access_token']},timeout=10)
  if r.status_code!=200:raise RuntimeError('Private status baseline failed')
  windows.append(dict(start=int(started//60)*60,requests=count+2))
 print(json.dumps(dict(client=client_id,windows=windows,latencies_ms=latencies)),flush=True)
"""

def run():
 config=json.loads(compose('config','--format','json'));assert config['name']=='ruang-guard'
 http=requests.Session();http.trust_env=False
 token=http.get(ADMIN+'session',timeout=10).json()['csrf']
 password=(ROOT/'secrets/initial-password.txt').read_text().strip()
 response=http.post(ADMIN+'login',json={'password':password},headers={'X-CSRF-Token':token},timeout=15)
 if response.status_code!=200:raise RuntimeError('Admin login failed; no credentials printed')
 csrf=response.json()['csrf'];original=http.get(ADMIN+'overview',timeout=10).json()['settings']
 def post(path,data):
  r=http.post(ADMIN+path,json=data,headers={'X-CSRF-Token':csrf},timeout=15);r.raise_for_status();return r.json()
 def wait(predicate,timeout=90):
  deadline=time.monotonic()+timeout
  while time.monotonic()<deadline:
   state=http.get(ADMIN+'ml',timeout=15).json()
   if predicate(state):return state
   time.sleep(3)
  raise RuntimeError('Expected live ML state not observed')
 names=['ruang-guard-baseline-'+str(i) for i in range(6)]
 for name in names:
  existing=subprocess.run(['docker','inspect',name],capture_output=True,cwd=ROOT)
  if existing.returncode==0:raise RuntimeError('Existing lab helper name; refusing to replace')
 started=math.ceil(time.time()/60)*60+60
 try:
  post('settings',dict(origin='ruang-warga',rate=120,window=60,duration=72))
  print('Collecting seven real minute windows from six local lab clients; no direct DB inserts.',flush=True)
  def actor(index):
   source='START='+str(started)+'\nACTOR='+str(index)+'\n'+CLIENT_SOURCE
   result=subprocess.run(['docker','compose','-p','ruang-guard','run','--rm','-T','--no-deps','--name',names[index],'gateway','python','-'],input=source,text=True,capture_output=True,cwd=ROOT,timeout=600)
   if result.returncode:raise RuntimeError('Controlled baseline client failed: '+str(index))
   return json.loads(result.stdout.strip())
  with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:receipts=list(pool.map(actor,range(6)))
  deadline=started+7*60+20
  while time.time()<deadline:time.sleep(min(3,deadline-time.time()))
  expected={(r['client'],w['start']) for r in receipts for w in r['windows']}
  def complete(state):return len([w for w in state['windows'] if (w['client'],w['start']) in expected and w['eligible']])>=40
  state=wait(complete)
  windows=[w for w in state['windows'] if (w['client'],w['start']) in expected and w['eligible']]
  assert len(windows)>=40
  post('ml/approve',{'ids':[w['id'] for w in windows]})
  model=post('ml/train',{'origin':'ruang-warga'})['id']
  state=wait(lambda s:any(m['id']==model and m['state'] in ('candidate','failed') for m in s['models']))
  candidate=next(m for m in state['models'] if m['id']==model)
  assert candidate['state']=='candidate' and candidate['metrics']['holdout_outlier_rate']<=.25,candidate['state']
  post('ml/activate',{'id':model});wait(lambda s:not s['worker']['stale'])
  print('Live baseline trained and candidate activated; testing one bounded behavioral anomaly.',flush=True)
  # 40 requests to a nonexistent fictional route, below configured rate. No payload or file access.
  begin=time.time()
  for _ in range(40):assert http.get(PUBLIC+'/lab-ml-observation',timeout=10).status_code==404
  bucket=int(begin//60)*60
  state=wait(lambda s:any(c['start']==bucket and c['state']=='ml_only' and c['model_id']==model for c in s['coordination']['cases']),timeout=100)
  finding=next(c for c in state['coordination']['cases'] if c['start']==bucket and c['state']=='ml_only' and c['model_id']==model)
  post('ml/review',{'id':finding['id'],'verdict':'suspicious'})
  assert post('ml/respond',{'id':finding['id']})['applied'] is True
  blocked=http.get(PUBLIC+'/api/health',timeout=10);assert blocked.status_code==429
  post('unblock',{'client':finding['client']});post('unblock',{'client':'login:'+finding['client']})
  assert http.get(PUBLIC+'/api/health',timeout=10).status_code==200
  values=sorted(ms for r in receipts for ms in r['latencies_ms'])
  result=dict(scope='Real controlled HTTP on localhost Docker lab; not production accuracy',model=model,baseline_windows=len(windows),training=candidate['metrics'],normal_get_requests=len(values),normal_get_latency_ms=dict(p50=values[math.ceil(.5*len(values))-1],p95=values[math.ceil(.95*len(values))-1],max=max(values)),behavioral_anomaly_detected=True,admin_response_429=True,manual_recovery_200=True,helper_sources=len({r['client'] for r in receipts}))
  output = ROOT/'test-results'
  output.mkdir(parents=True, exist_ok=True)
  (output/'live-ml-verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
  print(json.dumps(result,indent=2),flush=True)
 finally:
  post('settings',{k:original[k] for k in ['origin','rate','window','duration']})
  post('logout',{});http.close()
  for name in names:
   inspect=subprocess.run(['docker','inspect',name],capture_output=True,text=True,cwd=ROOT)
   if inspect.returncode==0:
    record=json.loads(inspect.stdout)[0]
    if record.get('Config',{}).get('Labels',{}).get('com.docker.compose.project')=='ruang-guard' and record.get('Name')=='/'+name:
     subprocess.run(['docker','rm','-f',name],capture_output=True,cwd=ROOT,check=True)
if __name__=='__main__':run()
