"""Temporary fictional metadata only; never seeds live logs or trains on live traffic."""
import json
import math
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from guard.core import Store
from guard import ml
from guard.admin import create_app


def normal_windows(store, clock, count=50):
    """Deterministic varied normal source/minute windows; test fixture, not real data."""
    start=60000
    for index in range(count):
        clock[0]=start+index*60+10
        for request in range(5+index%9):
            store.event('masked-source','POST' if request%3==0 else 'GET',
                        ['/','/api/health','/api/documents'][request%3],200,'allowed','forwarded',[],10+index%7,origin='one')
    clock[0]=start+count*60+1
    ml.collect(store)
    with store.db() as db:return [r[0] for r in db.execute("SELECT id FROM ml_windows WHERE origin='one' ORDER BY start")]


class MLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.password_hash=generate_password_hash('ml-test-only',method='scrypt')
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.clock=[60000.]
        self.origins={k:{'address':v,'port':8000,'health_path':'/api/health'} for k,v in [('one','172.30.10.10'),('two','172.30.10.20')]}
        self.store=Store(Path(self.tmp.name)/'db','test-only-key'*4,self.origins,now=lambda:self.clock[0])
        self.app=create_app(self.store,self.password_hash);self.client=self.app.test_client()
    def login(self):
        csrf=self.client.get('/admin/api/session').json['csrf']
        result=self.client.post('/admin/api/login',json={'password':'ml-test-only'},headers={'X-CSRF-Token':csrf})
        self.assertEqual(result.status_code,200);self.csrf=result.json['csrf']
    def post(self,action,data):return self.client.post('/admin/api/ml/'+action,json=data,headers={'X-CSRF-Token':self.csrf})
    def baseline(self):
        ids=normal_windows(self.store,self.clock);ml.approve(self.store,ids);return ids
    def test_migration_does_not_guess_old_origins(self):
        path=Path(self.tmp.name)/'legacy.db'
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE events(id INTEGER PRIMARY KEY,at REAL,client TEXT,method TEXT,route TEXT,status INTEGER,decision TEXT,reason TEXT,rules TEXT,ms REAL)')
            db.execute("INSERT INTO events VALUES(1,59900,'legacy','GET','/',200,'allowed','forwarded','[]',1)")
        store=Store(path,'test-only-key'*4,self.origins,now=lambda:self.clock[0]);ml.initialize(store);ml.collect(store)
        with store.db() as db:
            self.assertIsNone(db.execute('SELECT origin FROM events').fetchone()[0]);self.assertEqual(db.execute('SELECT COUNT(*) FROM ml_windows').fetchone()[0],0)
    def test_completed_windows_privacy_eligibility_and_origin_isolation(self):
        self.clock[0]=60010
        self.store.event('masked','GET','/api/documents/private-token',200,'allowed','forwarded',[],12,origin='one')
        self.store.event('masked','POST','/api/complaints',403,'blocked','waf_rule',[941100],5,origin='two')
        self.store.event('legacy','GET','/',200,'allowed','forwarded',[],1)
        ml.collect(self.store);self.assertFalse(ml.snapshot(self.store)['windows'])
        self.clock[0]=60061;ml.collect(self.store);ml.collect(self.store)
        with self.store.db() as db:
            rows=db.execute('SELECT * FROM ml_windows ORDER BY origin').fetchall();self.assertEqual(len(rows),2)
            self.assertEqual([r['eligible'] for r in rows],[1,0]);self.assertEqual(len(json.loads(rows[0]['features'])),len(ml.FEATURES))
        self.assertNotIn('private-token',json.dumps(ml.snapshot(self.store)))
        with self.assertRaises(ValueError):ml.approve(self.store,[rows[1]['id']])
    def test_auth_csrf_input_validation_and_readonly_status(self):
        self.assertEqual(self.client.get('/admin/api/ml').status_code,401);self.login()
        self.assertEqual(self.client.post('/admin/api/ml/train',json={'origin':'one'}).status_code,403)
        for action,data in [('approve',{'ids':[True]}),('approve',{'ids':[]}),('deactivate',{'id':True}),('activate',{'id':True}),('review',{'id':1,'verdict':[]}),('train',{'origin':[]}),('train',{'origin':'one','x':1})]:
            self.assertEqual(self.post(action,data).status_code,400)
        with self.store.db() as db:before=list(db.iterdump())
        self.assertEqual(self.client.get('/admin/api/ml').status_code,200)
        with self.store.db() as db:self.assertEqual(before,list(db.iterdump()))
    def test_baseline_required_frozen_and_temporal_split(self):
        self.login();self.assertEqual(self.post('train',{'origin':'one'}).status_code,400)
        ids=normal_windows(self.store,self.clock)
        self.assertEqual(self.post('train',{'origin':'one'}).status_code,400)
        self.assertEqual(self.post('approve',{'ids':ids}).status_code,200)
        response=self.post('train',{'origin':'one'});self.assertEqual(response.status_code,202)
        with self.store.db() as db:row=dict(db.execute('SELECT * FROM ml_models').fetchone())
        data=json.loads(row['dataset']);self.assertEqual(len(data['train']),40);self.assertEqual(len(data['holdout']),10)
        self.assertNotIn('masked-source',row['dataset']);self.assertLess(data['split_at'],data['cutoff'])
        self.assertEqual(self.post('train',{'origin':'one'}).status_code,400)
        self.clock[0]+=60;self.store.event('new','GET','/',200,'allowed','forwarded',[],1,origin='one');self.clock[0]+=60;ml.collect(self.store)
        with self.store.db() as db:self.assertEqual(db.execute('SELECT dataset FROM ml_models').fetchone()[0],row['dataset'])
    def test_reject_uniform_baseline_and_cross_origin_training(self):
        ids=normal_windows(self.store,self.clock)
        with self.store.db(True) as db:db.execute('UPDATE ml_windows SET features=?',(json.dumps([1,1,0,0,0,1]),))
        ml.approve(self.store,ids)
        with self.assertRaises(ValueError):ml.queue_training(self.store,'one')
        with self.assertRaises(ValueError):ml.queue_training(self.store,'two')
    def test_real_forest_activation_inference_review_and_restart(self):
        from guard.ml_engine import cycle,train_next,score_active,dataset,fit
        self.baseline();identifier=ml.queue_training(self.store,'one');self.assertEqual(train_next(self.store),identifier)
        state=ml.snapshot(self.store);candidate=state['models'][0];self.assertEqual(candidate['state'],'candidate')
        self.assertGreater(candidate['metrics']['train_count'],0);self.assertLessEqual(candidate['metrics']['holdout_outlier_rate'],.25)
        self.assertNotIn('dataset',candidate);self.assertEqual(state['mode'],'review_only');ml.activate(self.store,identifier)
        self.clock[0]+=60
        for i in range(400):self.store.event('burst','POST','/unknown',404,'allowed','forwarded',[],500,origin='one')
        self.clock[0]+=60;cycle(self.store,{})
        state=ml.snapshot(self.store);self.assertTrue(state['findings']);finding=state['findings'][0];self.assertGreater(finding['score'],0);self.assertIsNone(finding['review'])
        with self.store.db() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM blocks').fetchone()[0],0)
        ml.review(self.store,finding['id'],'normal');self.assertEqual(ml.snapshot(self.store)['pending'],0)
        score_active(self.store,{})
        self.assertEqual(ml.snapshot(self.store)['findings'][0]['review'],'normal')
        self.assertFalse(ml.snapshot(self.store)['worker']['stale']);self.clock[0]+=91;self.assertTrue(ml.snapshot(self.store)['worker']['stale'])
        with self.store.db() as db:row=dict(db.execute('SELECT * FROM ml_models').fetchone())
        rebuilt=fit(dataset(row));self.assertTrue(hasattr(rebuilt,'estimators_'))
        row['dataset']='malicious pickle content'
        with self.assertRaises(ValueError):dataset(row)
    def test_failed_candidate_preserves_active_and_rollback(self):
        from guard.ml_engine import train_next,score_active
        ids=self.baseline();first=ml.queue_training(self.store,'one');train_next(self.store);ml.activate(self.store,first)
        with self.store.db(True) as db:
            original=db.execute('SELECT dataset,digest,metrics,version FROM ml_models WHERE id=?',(first,)).fetchone()
            second=db.execute("INSERT INTO ml_models(origin,created_at,state,dataset,digest,metrics,version) VALUES('one',?,'candidate',?,?,?,?)",(self.clock[0],*original)).lastrowid
        ml.activate(self.store,second);ml.activate(self.store,first)
        with self.store.db(True) as db:
            bad=db.execute("INSERT INTO ml_models(origin,created_at,state,dataset,digest) VALUES('one',?,'queued','bad','bad')",(self.clock[0],)).lastrowid
        with self.assertRaises(ValueError):train_next(self.store)
        with self.store.db() as db:
            self.assertEqual(db.execute('SELECT state FROM ml_models WHERE id=?',(first,)).fetchone()[0],'active')
            self.assertEqual(db.execute('SELECT state FROM ml_models WHERE id=?',(bad,)).fetchone()[0],'failed')
        self.store.update('two',120,60,60);self.assertFalse(ml.snapshot(self.store)['models'])
        with self.assertRaises(ValueError):ml.activate(self.store,first)
    def test_api_candidate_activation_review_export_and_deactivation(self):
        from guard.ml_engine import train_next,cycle
        self.login();ids=normal_windows(self.store,self.clock)
        self.assertEqual(self.post('approve',{'ids':ids}).status_code,200)
        response=self.post('train',{'origin':'one'});self.assertEqual(response.status_code,202);identifier=response.json['id']
        train_next(self.store);self.assertEqual(self.post('activate',{'id':identifier}).status_code,200)
        self.clock[0]+=60
        for i in range(200):self.store.event('masked','POST','/unknown',404,'allowed','forwarded',[],500,origin='one')
        self.clock[0]+=60;cycle(self.store,{})
        state=self.client.get('/admin/api/ml').json;self.assertTrue(state['findings']);finding=state['findings'][0]
        self.assertEqual(self.post('review',{'id':finding['id'],'verdict':'suspicious'}).status_code,200)
        self.assertEqual(self.post('approve',{'ids':[finding['id']]}).status_code,400)
        report=self.client.get('/admin/api/reports?range=7d&format=json');self.assertEqual(report.status_code,200);self.assertTrue(report.json['ml_findings'])
        self.assertNotIn('dataset',report.text)
        self.assertEqual(self.post('deactivate',{'id':identifier}).status_code,200)
        self.assertFalse(any(m['state']=='active' for m in self.client.get('/admin/api/ml').json['models']))

    def test_version_mismatch_and_validation_gate(self):
        from guard.ml_engine import train_next,score_active
        self.baseline();identifier=ml.queue_training(self.store,'one');train_next(self.store)
        with self.store.db(True) as db:
            metrics=json.loads(db.execute('SELECT metrics FROM ml_models').fetchone()[0]);metrics['holdout_outlier_rate']=.9;db.execute('UPDATE ml_models SET metrics=?',(json.dumps(metrics),))
        with self.assertRaises(ValueError):ml.activate(self.store,identifier)
        metrics['holdout_outlier_rate']=0
        with self.store.db(True) as db:db.execute('UPDATE ml_models SET metrics=?',(json.dumps(metrics),))
        ml.activate(self.store,identifier)
        with self.store.db(True) as db:db.execute("UPDATE ml_models SET version='different'")
        self.assertEqual(score_active(self.store,{}),[identifier])
