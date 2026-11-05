"""Read-only, filtered views of the gateway's existing safe event metadata."""
from collections import Counter
import json


RANGES = {'15m': (900, 30), '1h': (3600, 120),
          '24h': (86400, 3600), '7d': (604800, 21600)}
PAGE_SIZES = {10, 25, 50, 100}
FIELDS = ('id', 'at', 'client', 'method', 'route', 'status',
          'decision', 'reason', 'rules', 'ms')
SEARCH_FIELDS = ('client', 'method', 'route', 'decision', 'status', 'reason', 'rules')


def _integer(value, default):
    if value is None:
        return default
    if not isinstance(value, str) or not value.isascii() or not value.isdigit() or len(value) > 7:
        raise ValueError('Invalid pagination')
    return int(value)


def parameters(args):
    allowed = {'range', 'q', 'page', 'page_size'}
    if any(key not in allowed or len(args.getlist(key)) != 1 for key in args):
        raise ValueError('Invalid statistics parameters')
    selected = args.get('range', '15m')
    query = args.get('q', '')
    page = _integer(args.get('page'), 1)
    size = _integer(args.get('page_size'), 25)
    if selected not in RANGES or len(query) > 200 or any(ord(char) < 32 for char in query):
        raise ValueError('Invalid statistics filter')
    if not 1 <= page <= 1_000_000 or size not in PAGE_SIZES:
        raise ValueError('Invalid statistics pagination')
    return selected, query.strip(), page, size


def summarize(store, args):
    selected, query, requested_page, size = parameters(args)
    rows, start, end, bucket_seconds = read_rows(store, selected, query)
    return aggregate(rows, selected, query, start, end, bucket_seconds, requested_page, size)


def read_rows(store, selected, query):
    duration, bucket_seconds = RANGES[selected]
    end = store.now()
    start = end - duration
    where = 'at >= ? AND at <= ?'
    values = [start, end]
    if query:
        # Identifiers come only from the fixed tuple; every user value is bound.
        # instr(), unlike LIKE, treats %, _ and backslash as literal characters.
        where += ' AND (' + ' OR '.join(
            f'instr(lower(CAST({field} AS TEXT)), lower(?)) > 0' for field in SEARCH_FIELDS) + ')'
        values.extend([query] * len(SEARCH_FIELDS))
    with store.db() as db:
        # Protect this connection against writes even if a future edit adds one.
        db.execute('PRAGMA query_only = ON')
        rows = [dict(row) for row in db.execute(
            'SELECT ' + ', '.join(FIELDS) + ' FROM events WHERE ' + where +
            ' ORDER BY at DESC, id DESC', values)]

    return rows, start, end, bucket_seconds


def aggregate(rows, selected, query, start, end, bucket_seconds, requested_page, size):
    count = RANGES[selected][0] // bucket_seconds
    buckets = [dict(at=start + index * bucket_seconds, total=0, allowed=0,
                    blocked=0, errors=0, active_sources=0) for index in range(count)]
    bucket_clients = [set() for _ in buckets]
    totals = dict(total=len(rows), allowed=0, blocked=0, errors=0, active_sources=0)
    sources, reasons = {}, Counter()
    decisions = {'allowed': 'allowed', 'blocked': 'blocked', 'error': 'errors'}
    for row in rows:
        index = min(count - 1, int((row['at'] - start) // bucket_seconds))
        bucket = buckets[index]
        bucket['total'] += 1
        bucket_clients[index].add(row['client'])
        source = sources.setdefault(row['client'], dict(
            client=row['client'], total=0, allowed=0, blocked=0, errors=0))
        source['total'] += 1
        decision = decisions.get(row['decision'])
        if decision:
            totals[decision] += 1
            bucket[decision] += 1
            source[decision] += 1
        if row['decision'] == 'blocked':
            reasons[row['reason']] += 1
    for index, clients in enumerate(bucket_clients):
        buckets[index]['active_sources'] = len(clients)
    totals['active_sources'] = len(sources)

    pages = (len(rows) + size - 1) // size
    page = min(requested_page, max(1, pages))
    events = rows[(page - 1) * size:page * size]
    for event in events:
        event['rules'] = json.loads(event['rules'])
    return {
        'range': selected, 'from': start, 'to': end, 'bucket_seconds': bucket_seconds,
        'query': query, 'totals': totals, 'buckets': buckets,
        'reasons': [{'reason': reason, 'count': value}
                    for reason, value in sorted(reasons.items(), key=lambda item: (-item[1], item[0]))],
        'sources': sorted(sources.values(), key=lambda source: (-source['total'], source['client']))[:10],
        'events': events,
        'pagination': {'page': page, 'page_size': size, 'total': len(rows), 'pages': pages},
    }
