"""Persistent, deduplicated local incidents. No external notification transport."""
import os
import requests
from .core import http_session


def policy():
    result = {}
    for key, env, default, low, high in [('threshold','ALERT_BLOCK_THRESHOLD',30,1,10000),('window','ALERT_WINDOW_SECONDS',60,15,3600),('failures','ALERT_FAILURE_COUNT',2,1,10)]:
        value = int(os.getenv(env, default))
        if not low <= value <= high: raise ValueError('Invalid alert policy')
        result[key] = value
    return result


def initialize(store):
    policy()
    with store.db(True) as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,kind TEXT,target TEXT,title TEXT,opened_at REAL,last_seen REAL,resolved_at REAL,acknowledged_at REAL,count INTEGER,resolution TEXT);
        CREATE UNIQUE INDEX IF NOT EXISTS alerts_active ON alerts(kind,target) WHERE resolved_at IS NULL;
        CREATE TABLE IF NOT EXISTS alert_monitor(id INTEGER PRIMARY KEY CHECK(id=1),at REAL,waf_failures INTEGER);''')


def check_waf(session_factory=http_session):
    try:
        with session_factory() as client:
            with client.post('http://waf:8081/inspect',json={'method':'GET','uri':'/api/health','headers':{'Host':'localhost:8090'},'body':'','client':'127.0.0.1'},timeout=(2,3),allow_redirects=False) as response:
                if response.status_code != 200: return False
                data=response.json()
                return data.get('allowed') is True and isinstance(data.get('rules'),list)
    except (requests.RequestException,ValueError,AttributeError):
        return False


def evaluate(store, waf_available):
    now=store.now(); config=policy(); origin=store.settings()['origin']
    with store.db(True) as db:
        previous=db.execute('SELECT * FROM alert_monitor WHERE id=1').fetchone()
        failures=0 if waf_available else (previous['waf_failures'] if previous and now-previous['at']<=45 else 0)+1
        db.execute('INSERT OR REPLACE INTO alert_monitor VALUES(1,?,?)',(now,failures))
        health=db.execute('SELECT * FROM health WHERE origin=? AND at<=? ORDER BY id DESC LIMIT ?', (origin,now,config['failures'])).fetchall()
        fresh=bool(health) and now-health[0]['at']<=45
        origin_down=fresh and len(health)==config['failures'] and all(not h['available'] for h in health) and now-health[-1]['at']<=config['failures']*30+15
        blocked=db.execute("SELECT COUNT(*) FROM events WHERE decision='blocked' AND at>? AND at<=?",(now-config['window'],now)).fetchone()[0]
        db.execute("UPDATE alerts SET resolved_at=?,resolution='origin_changed' WHERE kind='origin_unavailable' AND target<>? AND resolved_at IS NULL",(now,origin))
        conditions=[('origin_unavailable',origin,'Origin tidak tersedia',origin_down,fresh and bool(health[0]['available']),len(health)),('waf_unavailable','waf','WAF tidak tersedia',failures>=config['failures'],waf_available,failures),('blocked_spike','gateway','Lonjakan permintaan diblokir',blocked>=config['threshold'],blocked<config['threshold'],blocked)]
        for kind,target,title,active,recovered,count in conditions:
            row=db.execute('SELECT id FROM alerts WHERE kind=? AND target=? AND resolved_at IS NULL',(kind,target)).fetchone()
            if active:
                if row: db.execute('UPDATE alerts SET last_seen=?,count=? WHERE id=?',(now,count,row['id']))
                else: db.execute('INSERT INTO alerts(kind,target,title,opened_at,last_seen,count) VALUES(?,?,?,?,?,?)',(kind,target,title,now,now,count))
            elif row and recovered:
                db.execute("UPDATE alerts SET resolved_at=?,resolution=? WHERE id=?",(now,'below_threshold' if kind=='blocked_spike' else 'recovered',row['id']))
        db.execute('DELETE FROM alerts WHERE resolved_at IS NOT NULL AND (resolved_at<? OR id NOT IN (SELECT id FROM alerts ORDER BY id DESC LIMIT 1000))',(now-604800,))


def snapshot(store):
    with store.db() as db:
        rows=[dict(r) for r in db.execute('SELECT * FROM alerts ORDER BY resolved_at IS NOT NULL,id DESC LIMIT 100')]
        active=db.execute('SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL').fetchone()[0]
        unread=db.execute('SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL AND acknowledged_at IS NULL').fetchone()[0]
        monitor=db.execute('SELECT at FROM alert_monitor WHERE id=1').fetchone()
    return dict(alerts=rows,active_count=active,unacknowledged_count=unread,policy=policy(),monitor={'last_checked':monitor['at'] if monitor else None,'stale':not monitor or store.now()-monitor['at']>45})


def acknowledge(store, identifier):
    if type(identifier) is not int or identifier<1: raise ValueError('Invalid alert ID')
    with store.db(True) as db:
        row=db.execute('SELECT id FROM alerts WHERE id=?',(identifier,)).fetchone()
        if not row:return False
        db.execute('UPDATE alerts SET acknowledged_at=COALESCE(acknowledged_at,?) WHERE id=?',(store.now(),identifier))
        db.execute('INSERT INTO audit(at,action,target) VALUES(?,?,?)',(store.now(),'acknowledge_alert',str(identifier)))
    return True
