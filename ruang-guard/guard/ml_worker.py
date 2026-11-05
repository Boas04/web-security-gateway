"""Single ML worker, no listener, no network targets, no blocking decisions."""
import time
from .core import load_store
from .ml import initialize
from .ml_engine import cycle


def run():
    store=load_store()
    initialize(store)
    with store.db(True) as db:
        db.execute("UPDATE ml_models SET state='failed',error='worker_interrupted' WHERE state='training'")
    cache={}
    while True:
        try:
            cycle(store,cache)
        except Exception:
            with store.db(True) as db:
                db.execute("INSERT OR REPLACE INTO ml_runtime VALUES(1,?,'worker_failed')",(store.now(),))
            print('{"component":"ml","error":"worker_failed"}',flush=True)
        time.sleep(15)


if __name__=='__main__':run()
