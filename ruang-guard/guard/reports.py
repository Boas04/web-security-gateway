"""Downloadable, filtered metadata reports; never include raw request data."""
import csv
import io
import json
import math
from datetime import datetime, timezone
from werkzeug.datastructures import MultiDict


def export(store, args):
    if any(key not in {'range', 'q', 'format'} or len(args.getlist(key)) != 1 for key in args):
        raise ValueError('Invalid report parameters')
    format_name = args.get('format', 'json')
    if format_name not in {'json', 'csv'}:
        raise ValueError('Invalid report format')
    # One read snapshot. The statistics reader already reads all matching rows;
    # report pagination uses a private enlarged page size, not repeated reads.
    from .statistics import parameters, read_rows, aggregate
    selected, query, _, _ = parameters(MultiDict({'range': args.get('range', '24h'), 'q': args.get('q', '')}))
    rows, start, end, bucket_seconds = read_rows(store, selected, query)
    report = aggregate(rows, selected, query, start, end, bucket_seconds, 1, max(1, len(rows)))
    report['generated_at'] = datetime.fromtimestamp(end, timezone.utc).isoformat()
    report['scope'] = 'Stored safe metadata only; blocked requests include repeated temporary-block responses.'
    times = sorted(event['ms'] for event in report['events'])
    report['latency_ms'] = {'count': len(times), 'p50': times[math.ceil(len(times)*.5)-1] if times else None, 'p95': times[math.ceil(len(times)*.95)-1] if times else None, 'max': max(times) if times else None}
    # Operational histories use the time range, not the event text query.
    with store.db() as db:
        db.execute('PRAGMA query_only = ON')
        report['health'] = [dict(row) for row in db.execute('SELECT at,origin,available,status,ms FROM health WHERE at>=? AND at<=? ORDER BY at', (start,end))]
        report['incidents'] = [dict(row) for row in db.execute('SELECT kind,target,title,opened_at,last_seen,resolved_at,count,resolution FROM alerts WHERE opened_at<=? AND (resolved_at IS NULL OR resolved_at>=?) ORDER BY opened_at', (end,start))]
    report['history_scope'] = 'Health and incidents follow time range only. Recovery timestamps are recorded observations; no exact recovery duration is inferred.'
    from .ml import report as ml_report
    report['ml_findings'] = ml_report(store,start,end)
    from .coordination import snapshot as coordination_report
    report['coordination'] = coordination_report(store,start,end)
    report['ml_scope'] = 'Source-minute anomaly findings follow time range only, not event query. Scores are not probabilities; no automatic ML blocking.'
    if format_name == 'json':
        return json.dumps(report, ensure_ascii=False, indent=2), 'application/json', 'json'
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow(['id', 'time_utc', 'source_id', 'method', 'route', 'status', 'decision', 'reason', 'rule_ids', 'latency_ms'])
    def safe(value):
        value = str(value)
        return "'" + value if value.lstrip().startswith(('=', '+', '-', '@')) else value
    for event in report['events']:
        writer.writerow([safe(value) for value in [event['id'], datetime.fromtimestamp(event['at'], timezone.utc).isoformat(), event['client'], event['method'], event['route'], event['status'], event['decision'], event['reason'], ';'.join(map(str,event['rules'])), event['ms']]])
    return '\ufeff' + output.getvalue(), 'text/csv; charset=utf-8', 'csv'
