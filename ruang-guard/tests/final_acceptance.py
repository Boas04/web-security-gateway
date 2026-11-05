"""Final localhost-only Docker checks; restores services/settings in inherited cleanup."""
import json,time,unittest,secrets
from pathlib import Path
from integration import DockerIntegration,PUBLIC,ADMIN

class FinalAcceptance(DockerIntegration):
 def test_attack_families_with_actual_rule_ids(self):
  for name,payload,family in [('SQL injection',{'q':"1' OR '1'='1' --"},942),('XSS',{'q':'<script>alert(1)</script>'},941),('Path traversal',{'file':'../../../../fictional-secret.txt'},930),('Encoded traversal',{'file':'%2e%2e%2f%2e%2e%2ffictional-secret.txt'},930)]:
   with self.subTest(name=name):
    self.clear_blocks();self.change()
    before=self.admin.get(ADMIN+'overview',timeout=10).json()['events'];last=before[0]['id'] if before else 0
    result=self.http.get(PUBLIC+'/api/documents',params=payload,timeout=10)
    self.assertEqual(result.status_code,403,name)
    self.assertEqual(result.json()['code'],'security_restriction')
    events=self.admin.get(ADMIN+'overview',timeout=10).json()['events']
    self.assertTrue(any(e['id']>last and e['reason']=='waf_rule' and any(family*1000<=r<(family+1)*1000 for r in e['rules']) for e in events),name)
    self.assertEqual(self.http.get(PUBLIC+'/api/health',timeout=10).status_code,429)
    time.sleep(2.2);self.assertEqual(self.http.get(PUBLIC+'/api/health',timeout=10).status_code,200)
 def test_normal_input_false_positive_checks(self):
  for text in ['privasi',"O'Connor",'1 < 2','taman & lampu','SELECT kegiatan komunitas','Pelayanan warga Jakarta','Laporan fiktif 2026']:
   self.assertEqual(self.http.get(PUBLIC+'/api/documents',params={'q':text},timeout=10).status_code,200)
 def test_brute_force_real_csrf_session_and_login_recovery(self):
  import requests
  with requests.Session() as attacker:
   attacker.trust_env=False
   csrf=attacker.get(ADMIN+'session',timeout=10).json()['csrf'];seen=[]
   try:
    for _ in range(6):
     response=attacker.post(ADMIN+'login',json={'password':'incorrect-lab-'+secrets.token_hex(16)},headers={'X-CSRF-Token':csrf},timeout=10)
     seen.append(response.status_code)
     if response.status_code==429:break
    self.assertIn(401,seen);self.assertEqual(seen[-1],429)
    self.assertGreater(int(response.headers['Retry-After']),0)
    self.assertEqual(self.admin.get(ADMIN+'overview',timeout=10).status_code,200)
    self.assertEqual(self.http.get(PUBLIC+'/api/health',timeout=10).status_code,200)
   finally:self.clear_blocks()
 def test_progressive_expiry_real_gateway(self):
  self.change(rate=1,duration=2)
  for seconds in (2,4):
   self.assertEqual(self.http.get(PUBLIC+'/api/health',timeout=10).status_code,200)
   response=self.http.get(PUBLIC+'/api/health',timeout=10)
   self.assertEqual(response.status_code,429);self.assertEqual(int(response.headers['Retry-After']),seconds)
   time.sleep(seconds+.3)
  self.assertEqual(self.http.get(PUBLIC+'/api/health',timeout=10).status_code,200)

if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(FinalAcceptance)
 result=unittest.TextTestRunner(verbosity=2).run(suite)
 report=dict(scope='Actual localhost Docker, fictional lab only',tests=result.testsRun,passed=result.testsRun-len(result.failures)-len(result.errors),failures=len(result.failures),errors=len(result.errors),success=result.wasSuccessful())
 output = Path(__file__).resolve().parents[1]/'test-results'
 output.mkdir(parents=True, exist_ok=True)
 (output/'final-security.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
 raise SystemExit(0 if result.wasSuccessful() else 1)
