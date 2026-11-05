import tempfile,unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from guard.core import Store
class ProgressiveTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.now=1000.
  self.store=Store(Path(self.tmp.name)/'db','test-key'*8,{'one':dict(address='172.30.10.10',port=8000,health_path='/api/health')},now=lambda:self.now);self.store.update('one',1,60,72)
 def exceed(self,client='source',login=False):
  for _ in range(5 if login else 1):self.assertEqual(self.store.limit(client,login=login),(0,''))
  return self.store.limit(client,login=login)[0]
 def test_sequence_cap_and_no_extension(self):
  for expected in [72,144,288,576,1152,2304,3600,3600]:
   self.assertEqual(self.exceed(),expected)
   with self.store.db() as db:before=dict(db.execute('SELECT * FROM offenses').fetchone())
   self.now+=1;self.assertEqual(self.store.limit('source')[0],expected-1)
   with self.store.db() as db:self.assertEqual(before,dict(db.execute('SELECT * FROM offenses').fetchone()))
   self.now+=expected;self.store.cleanup()
 def test_reset_after_24h_and_manual_reset(self):
  self.assertEqual(self.exceed(),72);self.now+=73;self.assertEqual(self.exceed(),144)
  self.now+=86400;self.store.cleanup();self.assertEqual(self.exceed(),72)
  self.store.unblock('source');self.assertEqual(self.exceed(),72)
 def test_separate_sources_login_and_restart(self):
  self.assertEqual(self.exceed(),72);self.assertEqual(self.exceed('other'),72);self.assertEqual(self.exceed(login=True),300)
  self.now+=301;self.store.cleanup();self.store=Store(self.store.path,self.store.secret,self.store.origins,now=lambda:self.now)
  self.assertEqual(self.exceed(),144);self.assertEqual(self.exceed(login=True),600)
 def test_parallel_waf_hits_count_once(self):
  with ThreadPoolExecutor(max_workers=4) as pool:durations=list(pool.map(lambda _:self.store.block('source','waf_rule'),range(4)))
  self.assertEqual(durations,[72]*4)
  with self.store.db() as db:self.assertEqual(db.execute('SELECT level FROM offenses').fetchone()[0],1)
 def test_waf_repeated_after_expiry_escalates(self):
  self.assertEqual(self.store.block('source','waf_rule'),72);self.now+=73;self.store.cleanup();self.assertEqual(self.store.block('source','waf_rule'),144)
