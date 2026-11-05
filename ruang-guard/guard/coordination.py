"""Correlate retained metadata. Agreement is supporting evidence, never ground truth."""
import json
import math


def evidence(events):
    counts=dict(schema=1,total=len(events),waf_hits=0,waf_passed=0,
                policy_rejections=0,processing_errors=0,unknown=0,
                repeat_waf_blocks=0,rate_limit_hits=0,review_blocks=0,rules=[])
    rules=set()
    for event in events:
        if event['decision']=='blocked' and event['status']==403 and event['reason']=='waf_rule':
            counts['waf_hits']+=1
            values=json.loads(event['rules'])
            if not isinstance(values,list) or any(type(v) is not int for v in values):raise ValueError('invalid_rules')
            rules.update(values)
        elif event['decision']=='allowed':counts['waf_passed']+=1
        elif event['decision']=='blocked':counts['policy_rejections']+=1
        elif event['decision']=='error':counts['processing_errors']+=1
        else:counts['unknown']+=1
        if event['status']==429:
            if event['reason']=='waf_rule':counts['repeat_waf_blocks']+=1
            elif event['reason']=='rate_limit':counts['rate_limit_hits']+=1
            elif event['reason']=='ml_review':counts['review_blocks']+=1
    counts['rules']=sorted(rules)[:200]
    return counts


def parse_evidence(window):
    try:
        data=json.loads(window.get('evidence') or 'null')
        if not isinstance(data,dict) or data.get('schema')!=1 or data.get('total')!=window['requests']:return None
        keys=('total','waf_hits','waf_passed','policy_rejections','processing_errors','unknown',
              'repeat_waf_blocks','rate_limit_hits','review_blocks')
        if any(type(data.get(k)) is not int or data[k]<0 for k in keys):return None
        if data['total']<1 or any(data[k]>data['total'] for k in keys):return None
        if data['repeat_waf_blocks']+data['rate_limit_hits']+data['review_blocks']>data['policy_rejections']:return None
        if any(window.get(k) is not None and window[k]!=data[k] for k in ('waf_hits','processing_errors','policy_rejections')):return None
        if sum(data[k] for k in ('waf_hits','waf_passed','policy_rejections','processing_errors','unknown'))!=data['total']:return None
        if not isinstance(data.get('rules'),list) or len(data['rules'])>200 or any(type(v) is not int for v in data['rules']):return None
        return data
    except (ValueError,TypeError,KeyError):return None


def classify(window, model, health, now):
    facts=parse_evidence(window)
    ready=bool(model and model['state']=='active' and health and not health['error']
               and health.get('digest')==model.get('digest') and bool(model.get('digest'))
               and health.get('version')==model.get('version') and bool(model.get('version'))
               and -5<=now-health['checked_at']<=90 and window.get('model_id')==model['id']
               and type(window.get('anomaly')) is int and window['anomaly'] in (0,1)
               and type(window.get('score')) in (int,float) and math.isfinite(window['score'])
               and bool(window['score']>0)==bool(window['anomaly']))
    anomaly=bool(window.get('anomaly')) if ready else None
    if not facts or facts['unknown']:
        state,title,review,action='insufficient_evidence','Bukti tidak lengkap',False,'Periksa pengumpulan data; jangan simpulkan hasil bersih.'
    elif facts['processing_errors']:
        state,title,review,action='technical_failure','Ada request gagal diproses',False,'Periksa layanan WAF/origin; gangguan bukan konfirmasi serangan.'
    elif facts['waf_hits']:
        if anomaly is True:
            state,title='signals_aligned','WAF dan ML memberi sinyal'
        elif anomaly is False:
            state,title='disagreement','WAF menolak, ML tidak menandai'
        else:state,title='waf_only','Temuan WAF; ML belum dapat memvalidasi'
        review,action=True,'Pertahankan keputusan WAF dan tinjau bukti/aturan; hasil ML tidak membuka blokir.'
    elif anomaly is True:
        state,title,review,action='ml_only','Anomali ML tanpa temuan WAF',True,'Tinjau perilaku dan kemungkinan lonjakan normal sebelum tindakan.'
    elif facts['policy_rejections']:
        state,title,review,action='policy_only','Pembatasan kebijakan',False,'Periksa kuota/blokir aktif; 429 bukan deteksi WAF baru.'
    elif ready:
        state,title,review,action='no_alert','Tidak ada sinyal pada jendela ini',False,'Tetap pantau; ini bukan jaminan request aman.'
    else:
        state,title,review,action='ml_unavailable','ML belum dapat menilai',bool(window.get('anomaly')),'WAF tetap melindungi; periksa model aktif, umur data, dan kesehatan worker. Skor historis bukan validasi terkini.'
    return dict(state=state,title=title,needs_review=review,recommendation=action,
                evidence=facts,ml_available=ready,ml_anomaly=anomaly,
                can_respond=bool(review and ready and window.get('review')=='suspicious'
                                 and 0<=now-window['end']<=300))


def snapshot(store, start=None, end=None):
    origin=store.settings()['origin']
    with store.db() as db:
        models={r['id']:dict(r) for r in db.execute('SELECT id,state,digest,version FROM ml_models WHERE origin=?',(origin,))}
        health={r['model_id']:dict(r) for r in db.execute('SELECT * FROM ml_model_health')}
        if start is None:
            rows=[dict(r) for r in db.execute('SELECT * FROM ml_windows WHERE origin=? AND (anomaly=1 OR waf_hits>0 OR processing_errors>0 OR policy_rejections>0 OR evidence IS NULL) ORDER BY review IS NOT NULL,start DESC,id DESC LIMIT 100',(origin,))]
        else:
            rows=[dict(r) for r in db.execute('SELECT * FROM ml_windows WHERE start>=? AND end<=? AND (anomaly=1 OR waf_hits>0 OR processing_errors>0 OR policy_rejections>0 OR evidence IS NULL) ORDER BY start LIMIT 10000',(start,end))]
            models={r['id']:dict(r) for r in db.execute('SELECT id,state,digest,version FROM ml_models')}
        probe=db.execute('SELECT * FROM alert_monitor WHERE id=1').fetchone() if db.execute("SELECT 1 FROM sqlite_master WHERE name='alert_monitor'").fetchone() else None
        pending=db.execute('SELECT COUNT(*) FROM ml_windows WHERE origin=? AND review IS NULL AND evidence IS NOT NULL AND processing_errors=0 AND (anomaly=1 OR waf_hits>0)',(origin,)).fetchone()[0]
        response_ids={r[0] for r in db.execute('SELECT window_id FROM ml_responses')}
    now=store.now()
    cases=[]
    for row in rows:
        outcome=classify(row,models.get(row['model_id']),health.get(row['model_id']),now)
        outcome['can_respond']=outcome['can_respond'] and row['id'] not in response_ids
        cases.append(dict(id=row['id'],origin=row['origin'],client=row['client'],start=row['start'],end=row['end'],
                          requests=row['requests'],model_id=row['model_id'],score=row['score'],review=row['review'],
                          response_applied=row['id'] in response_ids,**outcome))
    waf_status='unknown' if not probe or not -5<=now-probe['at']<=45 else 'unavailable' if probe['waf_failures'] else 'available'
    return dict(cases=cases,pending=pending,waf_status=waf_status,waf_checked_at=probe['at'] if probe else None,
                scope='Source-minute correlation, not independent validation of payload safety; current model health gates actions.')


def respond(store, identifier):
    if type(identifier) is not int or identifier<1:raise ValueError('ID temuan tidak valid.')
    # Serialize review, evidence checks and response to avoid double clicks extending a block.
    with store.db(True) as db:
        row=db.execute('SELECT * FROM ml_windows WHERE id=?',(identifier,)).fetchone()
        if not row or row['origin']!=store.settings()['origin']:raise ValueError('Temuan origin aktif tidak ditemukan.')
        if db.execute('SELECT 1 FROM ml_responses WHERE window_id=?',(identifier,)).fetchone():return False
        model=db.execute('SELECT * FROM ml_models WHERE id=?',(row['model_id'],)).fetchone()
        health=db.execute('SELECT * FROM ml_model_health WHERE model_id=?',(row['model_id'],)).fetchone()
        from .ml import validate_dataset,check_lineage
        if not model:raise ValueError('Model tidak ditemukan.')
        check_lineage(db,validate_dataset(model))
        case=classify(dict(row),dict(model) if model else None,dict(health) if health else None,store.now())
        if not case['can_respond']:raise ValueError('Butuh temuan terbaru, model sehat, dan penilaian Mencurigakan oleh admin.')
        block=db.execute('SELECT * FROM blocks WHERE client=? AND expires>?',(row['client'],store.now())).fetchone()
        expiry=block['expires'] if block else store.now()+min(store.settings()['duration'],3600)
        if not block:
            db.execute("INSERT OR REPLACE INTO blocks(client,expires,reason) VALUES(?,?,'ml_review')",(row['client'],expiry))
        db.execute('INSERT INTO ml_responses(window_id,at,expires) VALUES(?,?,?)',(identifier,store.now(),expiry))
        db.execute("INSERT INTO audit(at,action,target) VALUES(?,'ml_review_block',?)",(store.now(),str(identifier)))
    return True
