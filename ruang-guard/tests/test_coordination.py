"""Decision matrix and control integration; temporary DBs, fictional sources, no network."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import requests
from werkzeug.security import generate_password_hash
from guard.core import Store
from guard.admin import create_app
from guard.gateway import create_app as gateway
from guard import ml,coordination
from guard.ml_engine import train_next,score_active,cycle
from test_ml import normal_windows


class CoordinationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.password_hash=generate_password_hash('coordination-test-only',method='scrypt')
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.clock=[60000.]
        self.origins={k:{'address':v,'port':8000,'health_path':'/api/health'} for k,v in [('one','172.30.10.10'),('two','172.30.10.20')]}
        self.store=Store(Path(self.tmp.name)/'db','test-key'*8,self.origins,now=lambda:self.clock[0]);self.client=create_app(self.store,self.password_hash).test_client()
    def login(self):
        csrf=self.client.get('/admin/api/session').json['csrf'];r=self.client.post('/admin/api/login',json={'password':'coordination-test-only'},headers={'X-CSRF-Token':csrf});self.assertEqual(r.status_code,200);self.csrf=r.json['csrf']
    def post(self,action,data):return self.client.post('/admin/api/ml/'+action,json=data,headers={'X-CSRF-Token':self.csrf})
    def ready(self):
        ids=normal_windows(self.store,self.clock);ml.approve(self.store,ids);identifier=ml.queue_training(self.store,'one');train_next(self.store);ml.activate(self.store,identifier);self.cache={};self.assertEqual(score_active(self.store,self.cache),[]);return identifier,ids
    def case(self,model_id,anomaly=1,waf=True):
        self.clock[0]=(int(self.clock[0]//60)+1)*60+10
        client=self.store.identity('127.0.0.1')
        self.store.event(client,'GET','/api/documents',403 if waf else 200,'blocked' if waf else 'allowed','waf_rule' if waf else 'forwarded',[941100] if waf else [],3,origin='one')
        self.clock[0]=(int(self.clock[0]//60)+1)*60+1;ml.collect(self.store)
        with self.store.db(True) as db:
            identifier=db.execute('SELECT id FROM ml_windows WHERE client=? ORDER BY start DESC LIMIT 1',(client,)).fetchone()[0]
            # Fixed scorer output for deterministic policy tests, not an ML accuracy claim.
            db.execute('UPDATE ml_windows SET model_id=?,score=?,anomaly=?,scored_at=? WHERE id=?',(model_id,.1 if anomaly else -.1,anomaly,self.clock[0],identifier))
        self.assertEqual(score_active(self.store,self.cache),[])
        return identifier,client
    def test_full_decision_matrix_and_missing_is_not_normal(self):
        event=dict(decision='blocked',status=403,reason='waf_rule',rules='[941100]')
        proof=coordination.evidence([event]);row=dict(requests=1,evidence=json.dumps(proof),model_id=1,score=.1,anomaly=1,end=60000,review=None)
        model=dict(id=1,state='active',digest='d',version='v');health=dict(checked_at=60001,error=None,digest='d',version='v')
        def state():return coordination.classify(row,model,health,60001)
        self.assertEqual(state()['state'],'signals_aligned');row.update(score=-.1,anomaly=0);self.assertEqual(state()['state'],'disagreement')
        row['model_id']=None;self.assertEqual(state()['state'],'waf_only');self.assertFalse(state()['ml_available'])
        row['model_id']=1;health['checked_at']=59900;self.assertEqual(state()['state'],'waf_only')
        health['checked_at']=60001;health['digest']='different';self.assertEqual(state()['state'],'waf_only')
        health['digest']='d';row.update(score=float('nan'),anomaly=1);self.assertFalse(state()['ml_available'])
        row.update(score=.1,anomaly=1);proof=coordination.evidence([dict(decision='allowed',status=200,reason='forwarded',rules='[]')]);row['evidence']=json.dumps(proof)
        self.assertEqual(state()['state'],'ml_only');row.update(score=-.1,anomaly=0);self.assertEqual(state()['state'],'no_alert')
        row.update(score=None,anomaly=None);self.assertEqual(state()['state'],'ml_unavailable')
        row.update(score=.1,anomaly=1);row['evidence']=json.dumps(coordination.evidence([dict(decision='error',status=503,reason='waf_unavailable',rules='[]')]))
        self.assertEqual(state()['state'],'technical_failure');self.assertFalse(state()['can_respond'])
        row.update(score=-.1,anomaly=0);row['evidence']=json.dumps(coordination.evidence([dict(decision='blocked',status=429,reason='waf_rule',rules='[]')]))
        self.assertEqual(state()['state'],'policy_only')
        row['evidence']=None;self.assertEqual(state()['state'],'insufficient_evidence')
    def test_waf_hit_is_distinct_from_repeat_and_policy_blocks(self):
        events=[dict(decision='blocked',status=403,reason='waf_rule',rules='[941100]')]+[dict(decision='blocked',status=429,reason='waf_rule',rules='[]') for _ in range(5)]+[dict(decision='blocked',status=429,reason='rate_limit',rules='[]')]
        proof=coordination.evidence(events);self.assertEqual(proof['waf_hits'],1);self.assertEqual(proof['repeat_waf_blocks'],5);self.assertEqual(proof['policy_rejections'],6);self.assertEqual(proof['rules'],[941100]);self.assertEqual(proof['rate_limit_hits'],1)
    def test_authenticated_response_needs_review_and_is_idempotent(self):
        model,_=self.ready();identifier,client=self.case(model,waf=False)
        self.assertEqual(self.client.post('/admin/api/ml/respond',json={'id':identifier}).status_code,403)
        self.login();self.assertEqual(self.post('respond',{'id':identifier}).status_code,400)
        self.assertEqual(self.post('review',{'id':identifier,'verdict':'suspicious'}).status_code,200)
        self.assertTrue(self.post('respond',{'id':identifier}).json['applied'])
        with self.store.db() as db:before=dict(db.execute('SELECT * FROM blocks WHERE client=?',(client,)).fetchone())
        self.clock[0]+=2;self.assertFalse(self.post('respond',{'id':identifier}).json['applied'])
        with self.store.db() as db:after=dict(db.execute('SELECT * FROM blocks WHERE client=?',(client,)).fetchone())
        self.assertEqual(before,after);self.assertEqual(after['reason'],'ml_review');self.assertEqual(self.store.limit('different-source'),(0,''))
        response=gateway(self.store,inspector=lambda *args:dict(allowed=True,rules=[])).test_client().get('/api/health');self.assertEqual(response.status_code,429)
        self.assertEqual(self.post('review',{'id':identifier,'verdict':'normal'}).status_code,200)
        self.assertGreater(self.store.limit(client)[0],0) # Review is not implicit unblocking.
        report=self.client.get('/admin/api/reports?range=7d&format=json').json;self.assertTrue(report['coordination']['cases']);self.assertNotIn('dataset',json.dumps(report))
    def test_existing_waf_block_never_extended_or_overwritten(self):
        model,_=self.ready();identifier,client=self.case(model);self.store.block(client,'waf_rule');ml.review(self.store,identifier,'suspicious')
        with self.store.db() as db:old=dict(db.execute('SELECT * FROM blocks').fetchone())
        self.assertTrue(coordination.respond(self.store,identifier))
        with self.store.db() as db:self.assertEqual(old,dict(db.execute('SELECT * FROM blocks').fetchone()))
    def test_stale_model_old_case_and_cross_origin_cannot_enforce(self):
        model,_=self.ready();identifier,_=self.case(model,waf=False);ml.review(self.store,identifier,'suspicious')
        self.clock[0]+=91
        with self.assertRaises(ValueError):coordination.respond(self.store,identifier)
        score_active(self.store,self.cache);self.clock[0]+=301;score_active(self.store,self.cache)
        with self.assertRaises(ValueError):coordination.respond(self.store,identifier)
        self.store.update('two',120,60,60)
        with self.assertRaises(ValueError):coordination.respond(self.store,identifier)
    def test_revoke_quarantines_model_without_unblocking(self):
        model,ids=self.ready();identifier,client=self.case(model);self.store.block(client,'waf_rule');ml.revoke_baseline(self.store,ids[0])
        with self.store.db() as db:self.assertEqual(db.execute('SELECT state FROM ml_models WHERE id=?',(model,)).fetchone()[0],'quarantined')
        self.assertGreater(self.store.limit(client)[0],0)
        with self.assertRaises(ValueError):ml.activate(self.store,model)
        case=coordination.snapshot(self.store)['cases'][0];self.assertFalse(case['ml_available']);self.assertEqual(case['state'],'waf_only')
    def test_cache_integrity_rechecked_and_waf_fail_closed(self):
        model,_=self.ready();identifier,_=self.case(model,anomaly=0);self.assertEqual(coordination.snapshot(self.store)['cases'][0]['state'],'disagreement')
        with self.store.db(True) as db:db.execute("UPDATE ml_models SET dataset='changed' WHERE id=?",(model,))
        self.assertEqual(score_active(self.store,self.cache),[model]);self.assertFalse(coordination.snapshot(self.store)['cases'][0]['ml_available'])
        guard=gateway(self.store,inspector=lambda *args:dict(allowed=False,rules=[941100])).test_client()
        self.assertEqual(guard.get('/api/health').status_code,403)
        self.store.unblock(self.store.identity('127.0.0.1'))
        def unavailable(*args):raise requests.ConnectionError('private marker')
        self.assertEqual(gateway(self.store,inspector=unavailable).test_client().get('/api/health').status_code,503)
    def test_candidate_failure_does_not_stop_healthy_scoring(self):
        model,_=self.ready()
        with self.store.db(True) as db:db.execute("INSERT INTO ml_models(origin,created_at,state,dataset,digest) VALUES('two',?,'queued','bad','bad')",(self.clock[0],))
        cycle(self.store,self.cache)
        with self.store.db() as db:self.assertIsNone(db.execute('SELECT error FROM ml_model_health WHERE model_id=?',(model,)).fetchone()[0])
    def test_retention_cannot_reuse_window_ids(self):
        self.clock[0]=60010;self.store.event('one','GET','/',200,'allowed','forwarded',[],1,origin='one');self.clock[0]=60061;ml.collect(self.store)
        with self.store.db(True) as db:
            old=db.execute('SELECT MAX(id) FROM ml_windows').fetchone()[0];db.execute('DELETE FROM ml_windows');db.execute('DELETE FROM events')
        ml.initialize(self.store);self.clock[0]=60130;self.store.event('two','GET','/',200,'allowed','forwarded',[],1,origin='one');self.clock[0]=60200;ml.collect(self.store)
        with self.store.db() as db:self.assertGreater(db.execute('SELECT MIN(id) FROM ml_windows').fetchone()[0],old)
    def test_legacy_evidence_not_guessed_and_status_get_is_readonly(self):
        self.clock[0]=60010;self.store.event('one','GET','/',200,'allowed','forwarded',[],1,origin='one');self.clock[0]=60061;ml.collect(self.store)
        with self.store.db(True) as db:db.execute('UPDATE ml_windows SET evidence=NULL,waf_hits=NULL');db.execute('DELETE FROM events')
        ml.collect(self.store);self.assertEqual(coordination.snapshot(self.store)['cases'][0]['state'],'insufficient_evidence')
        self.login()
        with self.store.db() as db:before=list(db.iterdump())
        self.assertEqual(self.client.get('/admin/api/ml').status_code,200)
        with self.store.db() as db:self.assertEqual(before,list(db.iterdump()))
