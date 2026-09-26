"""Download the model card (README.md) for every model in models.json.

Writes cards.jsonl.gz, one JSON object per line: {"id", "status", "card"}. status is the
HTTP status (200 = card saved, 404 = the repo has no README, 401/403 = gated or removed).
Re-running skips models already in the file, so an interrupted run can be resumed.

    python fetch_cards.py              # all models
    python fetch_cards.py --limit 100  # just the first 100 (for a quick test)
"""
import argparse
import gzip
import json
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

HERE = Path(__file__).parent
OUT = HERE / "cards.jsonl.gz"
URL = "https://huggingface.co/{id}/raw/main/README.md"
WORKERS = 4
# The Hub allows anonymous clients 3000 file requests per 5 minutes (10/s, from its
# RateLimit-Policy header); stay under that.
RATE = 8  # requests per second, across all workers
MAX_CARD = 200_000   # characters; a few cards embed huge tables or base64 images

local = threading.local()
backoff_until = 0.0  # shared: when rate-limited, every worker waits
backoff_lock = threading.Lock()
next_slot = 0.0      # shared pacing clock
pace_lock = threading.Lock()


def pace():
    global next_slot
    with pace_lock:
        now = time.time()
        next_slot = max(next_slot + 1 / RATE, now)
        wait = next_slot - now
    if wait > 0:
        time.sleep(wait)


def retry_delay(r, attempt):
    """Seconds until the rate-limit window resets, from 'RateLimit: ...;r=0;t=253'."""
    m = re.search(r"r=(\d+);t=(\d+)", r.headers.get("RateLimit", ""))
    if m and m.group(1) == "0":
        return int(m.group(2)) + 1
    return int(r.headers.get("Retry-After") or 3 * (attempt + 1))


def fetch(model_id):
    global backoff_until
    s = getattr(local, "s", None) or requests.Session()
    local.s = s
    for attempt in range(10):
        wait = backoff_until - time.time()
        if wait > 0:
            time.sleep(wait)
        pace()
        try:
            r = s.get(URL.format(id=model_id), timeout=60)
        except requests.RequestException:
            time.sleep(5 * (attempt + 1))
            continue
        if r.status_code == 429 or r.status_code >= 500:
            delay = retry_delay(r, attempt)
            with backoff_lock:
                backoff_until = max(backoff_until, time.time() + delay)
            continue
        card = r.text[:MAX_CARD] if r.status_code == 200 else None
        return {"id": model_id, "status": r.status_code, "card": card}
    return {"id": model_id, "status": "failed", "card": None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int)
    args = ap.parse_args()

    ids = [m["id"] for m in json.loads((HERE / "models.json").read_text())]
    done, kept, truncated = set(), [], False
    if OUT.exists():
        with gzip.open(OUT, "rt") as f:
            try:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # a line cut off by an interrupted run; refetched below
                    if rec["status"] != "failed":
                        done.add(rec["id"])
                        kept.append(line if line.endswith("\n") else line + "\n")
            except EOFError:
                truncated = True  # the run was killed mid-write
    if truncated:
        # Appending to a truncated gzip stream would corrupt it, so rewrite the good records.
        tmp = OUT.with_suffix(".tmp")
        with gzip.open(tmp, "wt") as f:
            f.writelines(kept)
        tmp.replace(OUT)
    todo = [i for i in ids if i not in done][: args.limit]
    print(f"{len(done)} already saved, {len(todo)} to fetch", file=sys.stderr)

    start, n, saved = time.time(), 0, 0
    with gzip.open(OUT, "at") as out, ThreadPoolExecutor(WORKERS) as pool:
        for rec in pool.map(fetch, todo):
            out.write(json.dumps(rec) + "\n")
            n += 1
            saved += rec["status"] == 200
            if n % 500 == 0 or n == len(todo):
                out.flush()
                rate = n / (time.time() - start)
                print(f"{n}/{len(todo)}  cards={saved}  {rate:.1f}/s  "
                      f"eta {(len(todo) - n) / rate / 60:.0f} min", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
