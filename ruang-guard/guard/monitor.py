import os
import time
from .core import load_store, check_health
from .alerts import initialize, evaluate, check_waf

def run():
    store = load_store()
    initialize(store)
    while True:
        try:
            check_health(store, os.getenv('PUBLIC_ORIGIN','http://localhost:8090').split('://',1)[1])
            evaluate(store, check_waf())
            store.cleanup()
        except Exception:
            print('{"component":"monitor","error":"check_failed"}', flush=True)
        time.sleep(15)

if __name__ == '__main__':
    run()
