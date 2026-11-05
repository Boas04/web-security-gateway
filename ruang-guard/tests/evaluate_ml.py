"""Offline synthetic ML evaluation. Never contacts a host, reads secrets, or changes live DB."""
import json
from pathlib import Path
import tempfile
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guard.core import Store
from guard import ml
from guard.ml_engine import cycle,train_next
from test_ml import normal_windows


def evaluate():
    clock=[60000.]
    with tempfile.TemporaryDirectory() as tmp:
        store=Store(Path(tmp)/'ml.db','fictional-test-key'*4,{'one':{'address':'172.30.10.10','port':8000,'health_path':'/api/health'}},now=lambda:clock[0])
        ml.initialize(store)
        ids=normal_windows(store,clock);ml.approve(store,ids)
        model_id=ml.queue_training(store,'one');train_next(store);ml.activate(store,model_id)
        labels={}
        for index in range(40):
            clock[0]=(int(clock[0]//60)+1)*60+10
            abnormal=index>=30
            labels[int(clock[0]//60)*60]=abnormal
            count=120 if abnormal else 5+index%9
            for request in range(count):
                store.event('evaluation-source','POST' if abnormal or request%3==0 else 'GET',
                    '/unknown' if abnormal else ['/','/api/health','/api/documents'][request%3],
                    404 if abnormal else 200,'allowed','forwarded',[],500 if abnormal else 10+index%7,origin='one')
        clock[0]=(int(clock[0]//60)+1)*60+1
        cycle(store,{})
        with store.db() as db:
            rows=db.execute('SELECT start,anomaly,score FROM ml_windows WHERE client=? ORDER BY start',('evaluation-source',)).fetchall()
        assert len(rows)==40 and all(r['anomaly'] is not None for r in rows)
        tp=sum(bool(r['anomaly']) and labels[int(r['start'])] for r in rows)
        fp=sum(bool(r['anomaly']) and not labels[int(r['start'])] for r in rows)
        fn=10-tp;tn=30-fp
        result=dict(scope='OFFLINE SYNTHETIC FIXTURE ONLY, NOT PRODUCTION ACCURACY',
            algorithm='IsolationForest',model_version=model_id,
            baseline_windows=50,temporal_training_windows=40,normal_holdout_windows=10,
            evaluation_windows=40,tp=tp,fp=fp,tn=tn,fn=fn,
            precision=tp/(tp+fp) if tp+fp else None,recall=tp/10,false_positive_rate=fp/30,
            holdout_metrics=ml.snapshot(store)['models'][0]['metrics'],
            note='Easy synthetic behavioral anomalies; not SQL/XSS classification or a public benchmark. No live data was altered.')
        from collections import Counter
        cases=ml.snapshot(store)['coordination']['cases']
        result['coordination_states']=dict(Counter(c['state'] for c in cases))
        with store.db() as db:result['automatic_blocks']=db.execute('SELECT COUNT(*) FROM blocks').fetchone()[0]
        assert result['automatic_blocks']==0
        assert tp>0,'Fixture anomaly detection failed'
        return result

if __name__=='__main__':
    result=evaluate()
    if len(sys.argv)==2:
        output=Path(sys.argv[1]);output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
