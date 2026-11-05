"""Run unit/in-process suite with dedicated real Coraza, only on local Docker lab."""
import json,os,subprocess,sys,time,unittest
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))

def run():
 name='ruang-guard-inspector-test'
 config=json.loads(subprocess.check_output(['docker','compose','-p','ruang-guard','config','--format','json'],cwd=ROOT,text=True))
 if config['name']!='ruang-guard':raise RuntimeError('Wrong lab')
 if subprocess.run(['docker','inspect',name],capture_output=True).returncode==0:raise RuntimeError('Test container already exists; refusing replacement')
 subprocess.run(['docker','run','-d','--rm','--name',name,'--label','com.docker.compose.project=ruang-guard','--memory','128m','-p','127.0.0.1:18081:8081','ruang-guard-waf'],check=True,stdout=subprocess.DEVNULL)
 try:
  with requests.Session() as client:
   client.trust_env=False
   for _ in range(30):
    try:
     if client.get('http://127.0.0.1:18081/inspect',timeout=2).status_code==404:break
    except requests.RequestException:pass
    time.sleep(1)
   else:raise RuntimeError('Dedicated Coraza inspector not ready')
  os.environ['WAF_TEST_URL']='http://127.0.0.1:18081/inspect'
  suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
  result=unittest.TextTestRunner(verbosity=2).run(suite)
  report=dict(scope='Temporary databases and real Coraza on dedicated localhost port',tests=result.testsRun,passed=result.testsRun-len(result.errors)-len(result.failures)-len(result.skipped),skipped=len(result.skipped),failures=len(result.failures),errors=len(result.errors),success=result.wasSuccessful())
  output = ROOT/'test-results'
  output.mkdir(parents=True, exist_ok=True)
  (output/'unit-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
  return 0 if result.wasSuccessful() else 1
 finally:subprocess.run(['docker','stop',name],check=True,stdout=subprocess.DEVNULL)
if __name__=='__main__':raise SystemExit(run())
