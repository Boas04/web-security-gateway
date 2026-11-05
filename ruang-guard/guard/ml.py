"""ML data/control plane. Standard library only; never runs training in HTTP handlers."""
import hashlib
import json
import math
from collections import defaultdict

FEATURES = ['log_requests', 'log_routes', 'post_ratio', 'unknown_route_ratio',
            'http_error_ratio', 'log_mean_ms']
MIN_SAMPLES = 40  # Lab floor, not evidence of statistical sufficiency for deployment.
MAX_SAMPLES = 2000
MAX_HOLDOUT_RATE = .25


def initialize(store):
    with store.db(True) as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS ml_windows(
          id INTEGER PRIMARY KEY,origin TEXT,client TEXT,start REAL,end REAL,
          features TEXT,requests INTEGER,eligible INTEGER,approved_at REAL,
          model_id INTEGER,score REAL,anomaly INTEGER,review TEXT,reviewed_at REAL,
          UNIQUE(origin,client,start));
        CREATE TABLE IF NOT EXISTS ml_models(
          id INTEGER PRIMARY KEY,origin TEXT,created_at REAL,state TEXT,dataset TEXT,
          digest TEXT,metrics TEXT,version TEXT,activated_at REAL,error TEXT);
        CREATE UNIQUE INDEX IF NOT EXISTS ml_active ON ml_models(origin) WHERE state='active';
        CREATE UNIQUE INDEX IF NOT EXISTS ml_pending ON ml_models(origin) WHERE state IN ('queued','training');
        CREATE TABLE IF NOT EXISTS ml_runtime(id INTEGER PRIMARY KEY CHECK(id=1),at REAL,error TEXT);
        CREATE TABLE IF NOT EXISTS ml_model_health(model_id INTEGER PRIMARY KEY,checked_at REAL,error TEXT);
        CREATE TABLE IF NOT EXISTS ml_responses(window_id INTEGER PRIMARY KEY,at REAL,expires REAL);
        CREATE TABLE IF NOT EXISTS ml_sequence(id INTEGER PRIMARY KEY CHECK(id=1),value INTEGER);
        ''')
        # Serialize additive migration across admin/worker startup.
        db.execute('BEGIN IMMEDIATE')
        columns={r['name'] for r in db.execute('PRAGMA table_info(ml_windows)')}
        for name,kind in [('evidence','TEXT'),('waf_hits','INTEGER'),('processing_errors','INTEGER'),('policy_rejections','INTEGER'),('scored_at','REAL')]:
            if name not in columns:db.execute(f'ALTER TABLE ml_windows ADD COLUMN {name} {kind}')
        health_columns={r['name'] for r in db.execute('PRAGMA table_info(ml_model_health)')}
        for name in ('digest','version'):
            if name not in health_columns:db.execute(f'ALTER TABLE ml_model_health ADD COLUMN {name} TEXT')
        db.execute('INSERT OR IGNORE INTO ml_sequence VALUES(1,0)')
        db.execute('UPDATE ml_sequence SET value=MAX(value,COALESCE((SELECT MAX(id) FROM ml_windows),0)) WHERE id=1')


def validate_dataset(row):
    """Only bounded numeric data and source lineage; no executable serialized objects."""
    raw=row['dataset']
    if not isinstance(raw,str) or len(raw)>2_000_000 or hashlib.sha256(raw.encode()).hexdigest()!=row['digest']:
        raise ValueError('invalid_dataset')
    data=json.loads(raw)
    if data.get('schema')!=2 or data.get('features')!=FEATURES or data.get('origin')!=row['origin']:
        raise ValueError('invalid_schema_or_origin')
    all_ids=[]
    for name in ('train','holdout'):
        values=data.get(name);ids=data.get(name+'_ids')
        if not isinstance(values,list) or not 1<=len(values)<=MAX_SAMPLES or not isinstance(ids,list) or len(ids)!=len(values):
            raise ValueError('invalid_samples')
        for vector in values:
            if not isinstance(vector,list) or len(vector)!=len(FEATURES) or any(type(v) not in (int,float) or not math.isfinite(v) or not 0<=v<=1e6 for v in vector):raise ValueError('invalid_features')
        if any(type(i) is not int or i<1 for i in ids):raise ValueError('invalid_lineage')
        all_ids+=ids
    if len(set(all_ids))!=len(all_ids):raise ValueError('overlapping_lineage')
    if any(type(data.get(k)) not in (int,float) or not math.isfinite(data[k]) for k in ('cutoff','split_at')) or data['split_at']>=data['cutoff']:
        raise ValueError('invalid_cutoff')
    return data


def check_lineage(db, data):
    # Retention of old source rows is allowed; explicit revocation is not.
    expected={identifier:(vector,part) for part in ('train','holdout') for identifier,vector in zip(data[part+'_ids'],data[part])}
    for row in db.execute('SELECT id,origin,features,review,approved_at,eligible,start,end FROM ml_windows'):
        if row['id'] not in expected:continue
        vector,part=expected[row['id']]
        if row['origin']!=data['origin'] or row['review']!='normal' or not row['approved_at'] or not row['eligible'] or json.loads(row['features'])!=vector:
            raise ValueError('baseline_revoked_or_changed')
        if (part=='train' and row['end']>data['split_at']) or (part=='holdout' and row['start']<data['split_at']) or row['end']>data['cutoff']:
            raise ValueError('invalid_temporal_lineage')


def collect(store):
    """Only completed, non-overlapping source/minute windows; no raw request content."""
    end = math.floor(store.now()/60)*60
    with store.db() as db:
        rows = db.execute('SELECT at,origin,client,method,route,status,decision,reason,rules,ms FROM events WHERE origin IS NOT NULL AND at>=? AND at<? ORDER BY at,id LIMIT 10000', (end-7*86400,end)).fetchall()
        truncated=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]>=10000
    groups = defaultdict(list)
    for row in rows:
        if row['origin'] in store.origins:
            groups[(row['origin'],row['client'],math.floor(row['at']/60)*60)].append(row)
    with store.db(True) as db:
        for (origin,client,start), events in groups.items():
            # An oldest retained minute may be partial after event retention.
            if truncated and rows and start<=math.floor(rows[0]['at']/60)*60:continue
            n = len(events)
            features = [math.log1p(n), math.log1p(len({r['route'] for r in events})),
                        sum(r['method']=='POST' for r in events)/n,
                        sum(r['route']=='[other]' for r in events)/n,
                        sum(r['status']>=400 for r in events)/n,
                        math.log1p(sum(min(max(r['ms'],0),60000) for r in events)/n)]
            eligible = all(r['decision']=='allowed' and 200<=r['status']<400 for r in events)
            from .coordination import evidence
            proof=evidence(events)
            if not db.execute('SELECT 1 FROM ml_windows WHERE origin=? AND client=? AND start=?',(origin,client,start)).fetchone():
                db.execute('UPDATE ml_sequence SET value=value+1 WHERE id=1')
                identifier=db.execute('SELECT value FROM ml_sequence WHERE id=1').fetchone()[0]
                db.execute('INSERT INTO ml_windows(id,origin,client,start,end,features,requests,eligible,evidence,waf_hits,processing_errors,policy_rejections) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                           (identifier,origin,client,start,start+60,json.dumps(features),n,int(eligible),json.dumps(proof),proof['waf_hits'],proof['processing_errors'],proof['policy_rejections']))
            # Backfill evidence only if all source events are still retained.
            db.execute('UPDATE ml_windows SET evidence=?,waf_hits=?,processing_errors=?,policy_rejections=? WHERE origin=? AND client=? AND start=? AND requests=? AND evidence IS NULL',
                       (json.dumps(proof),proof['waf_hits'],proof['processing_errors'],proof['policy_rejections'],origin,client,start,n))
        db.execute('DELETE FROM ml_windows WHERE end<? OR id NOT IN (SELECT id FROM ml_windows ORDER BY id DESC LIMIT 10000)',(end-7*86400,))
        db.execute('DELETE FROM ml_responses WHERE window_id NOT IN (SELECT id FROM ml_windows)')


def audit(db, store, action, target):
    db.execute('INSERT INTO audit(at,action,target) VALUES(?,?,?)',(store.now(),action,str(target)))


def approve(store, identifiers):
    if not isinstance(identifiers,list) or not 1<=len(identifiers)<=100 or any(type(i) is not int or i<1 for i in identifiers) or len(set(identifiers))!=len(identifiers):
        raise ValueError('Pilih 1–100 jendela trafik normal.')
    with store.db(True) as db:
        for identifier in identifiers:
            row = db.execute('SELECT * FROM ml_windows WHERE id=?',(identifier,)).fetchone()
            if not row or row['origin']!=store.settings()['origin'] or not row['eligible'] or row['review']=='suspicious':
                raise ValueError('Data tidak memenuhi syarat baseline normal.')
            db.execute("UPDATE ml_windows SET approved_at=COALESCE(approved_at,?),review='normal',reviewed_at=? WHERE id=?",(store.now(),store.now(),identifier))
        audit(db,store,'ml_approve_baseline',len(identifiers))


def queue_training(store, origin):
    if origin not in store.origins or origin!=store.settings()['origin']:
        raise ValueError('Pilih origin aktif yang diizinkan.')
    with store.db(True) as db:
        if db.execute("SELECT 1 FROM ml_models WHERE origin=? AND state IN ('queued','training')",(origin,)).fetchone():
            raise ValueError('Pelatihan origin ini masih berjalan.')
        if db.execute('SELECT COUNT(*) FROM ml_models WHERE origin=?',(origin,)).fetchone()[0]>=50:
            raise ValueError('Batas 50 versi lab tercapai; arsipkan database sebelum eksperimen berikutnya.')
        rows = db.execute("SELECT id,start,end,features FROM ml_windows WHERE origin=? AND approved_at IS NOT NULL AND eligible=1 AND review='normal' ORDER BY start DESC,id DESC LIMIT ?",(origin,MAX_SAMPLES)).fetchall()
        rows = sorted(rows,key=lambda r:r['start'])
        if len(rows)<MIN_SAMPLES:
            raise ValueError('Minimal 40 jendela normal yang disetujui diperlukan.')
        boundary = rows[int(len(rows)*.8)]['start']
        train = [json.loads(r['features']) for r in rows if r['end']<=boundary]
        holdout = [json.loads(r['features']) for r in rows if r['start']>=boundary]
        if len(train)<30 or len(holdout)<8:
            raise ValueError('Butuh minimal 30 sampel latih dan 8 validasi pada menit yang berbeda.')
        if len({tuple(v) for v in train})<5:
            raise ValueError('Pola baseline terlalu seragam untuk pelatihan yang bermakna.')
        dataset = json.dumps(dict(schema=2,origin=origin,features=FEATURES,train=train,holdout=holdout,
                                  train_ids=[r['id'] for r in rows if r['end']<=boundary],
                                  holdout_ids=[r['id'] for r in rows if r['start']>=boundary],
                                  split_at=boundary,cutoff=max(r['end'] for r in rows)),sort_keys=True)
        digest = hashlib.sha256(dataset.encode()).hexdigest()
        if db.execute('SELECT 1 FROM ml_models WHERE origin=? AND digest=? AND state NOT IN (\'failed\',\'rejected\')',(origin,digest)).fetchone():
            raise ValueError('Baseline belum berubah; tambahkan data normal yang telah ditinjau.')
        identifier = db.execute("INSERT INTO ml_models(origin,created_at,state,dataset,digest) VALUES(?,?,'queued',?,?)",(origin,store.now(),dataset,digest)).lastrowid
        audit(db,store,'ml_queue_training',identifier)
        return identifier


def activate(store, identifier):
    if type(identifier) is not int or identifier<1: raise ValueError('ID model tidak valid.')
    with store.db(True) as db:
        row = db.execute('SELECT * FROM ml_models WHERE id=?',(identifier,)).fetchone()
        if not row or row['origin']!=store.settings()['origin'] or row['state'] not in {'candidate','superseded'}:
            raise ValueError('Model tidak dapat diaktifkan.')
        metrics = json.loads(row['metrics'])
        data=validate_dataset(row)
        check_lineage(db,data)
        if metrics.get('train_count')!=len(data['train']) or metrics.get('holdout_count')!=len(data['holdout']) or metrics.get('feature_schema')!=2 or metrics.get('cutoff')!=data['cutoff']:
            raise ValueError('Metadata evaluasi tidak sesuai dataset.')
        if type(metrics.get('holdout_outlier_rate')) not in (int,float) or not math.isfinite(metrics['holdout_outlier_rate']) or not 0<=metrics['holdout_outlier_rate']<=MAX_HOLDOUT_RATE:
            raise ValueError('Terlalu banyak baseline validasi ditandai anomali; periksa data dahulu.')
        db.execute("UPDATE ml_models SET state='superseded' WHERE origin=? AND state='active'",(row['origin'],))
        db.execute("UPDATE ml_models SET state='active',activated_at=? WHERE id=?",(store.now(),identifier))
        audit(db,store,'ml_activate',identifier)


def review(store, identifier, verdict):
    if type(identifier) is not int or identifier<1 or not isinstance(verdict,str) or verdict not in {'normal','suspicious'}:
        raise ValueError('Penilaian tidak valid.')
    with store.db(True) as db:
        row = db.execute('SELECT * FROM ml_windows WHERE id=?',(identifier,)).fetchone()
        if not row or row['origin']!=store.settings()['origin'] or not (row['anomaly'] or row['waf_hits']): raise ValueError('Temuan tidak ditemukan.')
        db.execute('UPDATE ml_windows SET review=?,reviewed_at=?,approved_at=NULL WHERE id=?',(verdict,store.now(),identifier))
        audit(db,store,'ml_review_'+verdict,identifier)


def deactivate(store, identifier):
    if type(identifier) is not int or identifier<1:raise ValueError('ID model tidak valid.')
    with store.db(True) as db:
        row=db.execute("SELECT origin FROM ml_models WHERE id=? AND state='active'",(identifier,)).fetchone()
        if not row or row['origin']!=store.settings()['origin']:raise ValueError('Model aktif tidak ditemukan.')
        db.execute("UPDATE ml_models SET state='superseded' WHERE id=?",(identifier,))
        audit(db,store,'ml_deactivate',identifier)


def revoke_baseline(store, identifier):
    if type(identifier) is not int or identifier<1:raise ValueError('ID baseline tidak valid.')
    with store.db(True) as db:
        row=db.execute('SELECT * FROM ml_windows WHERE id=?',(identifier,)).fetchone()
        if not row or row['origin']!=store.settings()['origin'] or not row['approved_at']:raise ValueError('Baseline tidak ditemukan.')
        db.execute("UPDATE ml_windows SET approved_at=NULL,review='suspicious',reviewed_at=? WHERE id=?",(store.now(),identifier))
        for model in db.execute("SELECT * FROM ml_models WHERE origin=? AND state NOT IN ('failed','quarantined')",(row['origin'],)).fetchall():
            try:
                data=validate_dataset(model)
                if identifier not in data['train_ids']+data['holdout_ids']:continue
            except ValueError:
                pass
            db.execute("UPDATE ml_models SET state='quarantined',error='baseline_revoked' WHERE id=?",(model['id'],))
            db.execute("INSERT OR REPLACE INTO ml_model_health(model_id,checked_at,error) VALUES(?,?,'baseline_revoked')",(model['id'],store.now()))
        audit(db,store,'ml_revoke_baseline',identifier)


def snapshot(store):
    origin = store.settings()['origin']
    with store.db() as db:
        models = [dict(r) for r in db.execute('SELECT m.id,m.origin,m.created_at,m.state,m.metrics,m.version,m.activated_at,m.error,h.checked_at,h.error AS health_error FROM ml_models m LEFT JOIN ml_model_health h ON h.model_id=m.id WHERE m.origin=? ORDER BY m.id DESC LIMIT 20',(origin,))]
        for model in models: model['metrics']=json.loads(model['metrics']) if model['metrics'] else None
        windows = [dict(r) for r in db.execute('SELECT * FROM ml_windows WHERE origin=? ORDER BY start DESC,id DESC LIMIT 100',(origin,))]
        for window in windows: window['features']=dict(zip(FEATURES,json.loads(window['features'])))
        approved = db.execute("SELECT COUNT(*) FROM ml_windows WHERE origin=? AND approved_at IS NOT NULL AND eligible=1 AND review='normal'",(origin,)).fetchone()[0]
        pending = db.execute('SELECT COUNT(*) FROM ml_windows WHERE origin=? AND anomaly=1 AND review IS NULL',(origin,)).fetchone()[0]
        findings = [dict(r) for r in db.execute('SELECT id,origin,client,start,end,requests,score,model_id,review,reviewed_at FROM ml_windows WHERE origin=? AND anomaly=1 ORDER BY review IS NOT NULL,start DESC LIMIT 100',(origin,))]
        runtime = db.execute('SELECT at,error FROM ml_runtime WHERE id=1').fetchone()
    from .coordination import snapshot as coordination_snapshot
    return dict(origin=origin,mode='review_only',algorithm='IsolationForest',features=FEATURES,
                models=models,windows=windows,findings=findings,approved=approved,pending=pending,
                coordination=coordination_snapshot(store),
                minimum=MIN_SAMPLES,worker={'last_checked':runtime['at'] if runtime else None,
                'stale':not runtime or store.now()-runtime['at']>90,'error':runtime['error'] if runtime else None})


def report(store, start, end):
    with store.db() as db:
        return [dict(r) for r in db.execute('SELECT origin,client,start,end,requests,model_id,score,review,reviewed_at FROM ml_windows WHERE anomaly=1 AND start>=? AND end<=? ORDER BY start',(start,end))]
