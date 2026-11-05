"""Real scikit-learn Isolation Forest training and inference, outside the proxy path."""
import json
import math
import sklearn
from sklearn.ensemble import IsolationForest
from .ml import FEATURES, validate_dataset, check_lineage


def dataset(row):
    return validate_dataset(row)


def fit(data):
    model = IsolationForest(n_estimators=128, max_samples=min(256,len(data['train'])),
                            contamination=.05, random_state=42, n_jobs=1)
    model.fit(data['train'])
    return model


def train_next(store):
    with store.db(True) as db:
        row = db.execute("SELECT * FROM ml_models WHERE state='queued' ORDER BY id LIMIT 1").fetchone()
        if not row:return None
        db.execute("UPDATE ml_models SET state='training' WHERE id=?",(row['id'],))
    try:
        data = dataset(row)
        model = fit(data)
        scores = model.decision_function(data['holdout'])
        metrics = dict(train_count=len(data['train']), holdout_count=len(data['holdout']),
                       holdout_outlier_rate=float(sum(scores<0)/len(scores)),
                       split_at=data['split_at'], cutoff=data['cutoff'],
                       train_score_min=float(min(model.decision_function(data['train']))),
                       random_state=42,contamination=.05,feature_schema=2,
                       evaluation='Chronological administrator-approved normal holdout; not attack precision/recall.')
        with store.db(True) as db:
            check_lineage(db,data)
            db.execute("UPDATE ml_models SET state='candidate',metrics=?,version=?,error=NULL WHERE id=? AND state='training'",(json.dumps(metrics),sklearn.__version__,row['id']))
    except Exception:
        with store.db(True) as db:
            db.execute("UPDATE ml_models SET state='failed',error='training_failed' WHERE id=? AND state='training'",(row['id'],))
        raise
    return row['id']


def score_active(store, cache):
    with store.db() as db:
        models = [dict(r) for r in db.execute("SELECT * FROM ml_models WHERE state='active'")]
    active_ids = {r['id'] for r in models}
    for old in list(cache):
        if old not in active_ids:del cache[old]
    failures=[]
    for row in models:
        try:
            # Validate on every pass, including cache hits and periods without traffic.
            data=dataset(row)
            if row['version']!=sklearn.__version__:raise ValueError('model_version_mismatch')
            with store.db() as db:check_lineage(db,data)
            cached=cache.get(row['id'])
            if not cached or cached[0]!=row['digest']:
                cache[row['id']] = (row['digest'],fit(data),data['cutoff'])
            _,model,cutoff=cache[row['id']]
            with store.db() as db:
                windows=db.execute('SELECT id,features FROM ml_windows WHERE origin=? AND start>=? AND model_id IS NULL ORDER BY start,id LIMIT 200',(row['origin'],cutoff)).fetchall()
            vectors=[json.loads(w['features']) for w in windows]
            if any(not isinstance(v,list) or len(v)!=len(FEATURES) or any(type(x) not in (int,float) or not math.isfinite(x) or not 0<=x<=1e6 for x in v) for v in vectors):raise ValueError('invalid_scoring_features')
            scores=model.decision_function(vectors) if vectors else []
            if any(not math.isfinite(float(s)) for s in scores):raise ValueError('invalid_score')
            with store.db(True) as db:
                current=db.execute('SELECT state,digest,version FROM ml_models WHERE id=?',(row['id'],)).fetchone()
                if not current or current['state']!='active' or current['digest']!=row['digest'] or current['version']!=row['version']:
                    cache.pop(row['id'],None);continue
                check_lineage(db,data)
                for window, score in zip(windows,scores):
                    db.execute('UPDATE ml_windows SET model_id=?,score=?,anomaly=?,scored_at=? WHERE id=? AND model_id IS NULL',
                               (row['id'],float(-score),int(score<0),store.now(),window['id']))
                db.execute('INSERT OR REPLACE INTO ml_model_health(model_id,checked_at,error,digest,version) VALUES(?,?,NULL,?,?)',(row['id'],store.now(),row['digest'],row['version']))
        except Exception:
            cache.pop(row['id'],None);failures.append(row['id'])
            with store.db(True) as db:
                db.execute("INSERT OR REPLACE INTO ml_model_health(model_id,checked_at,error,digest,version) VALUES(?,?,'model_validation_or_scoring_failed',?,?)",(row['id'],store.now(),row['digest'],row['version']))
    return failures


def cycle(store, cache):
    from .ml import collect
    collect(store)
    training_error=False
    try:train_next(store)
    except Exception:training_error=True
    failures=score_active(store,cache)
    # A bad candidate/model does not stop scoring other healthy active origins.
    error='model_unavailable' if failures else 'candidate_training_failed' if training_error else None
    with store.db(True) as db:
        db.execute('INSERT OR REPLACE INTO ml_runtime VALUES(1,?,?)',(store.now(),error))
