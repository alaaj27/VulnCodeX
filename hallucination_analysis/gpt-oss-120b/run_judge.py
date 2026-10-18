"""Judge every sampled record with gpt-oss-120b served locally by vLLM, one request per record.

Server (one A100 80GB GPU):
    vllm serve openai/gpt-oss-120b \
        --port 8011 --max-model-len 32768 --gpu-memory-utilization 0.92
Usage:  python hallucination_analysis/gpt-oss-120b/run_judge.py [--limit N] [--workers 64] [--effort medium]
Reads:  ../sample_records.json, ../prompt.md
Writes: raw/<record id>.json   (full response plus seconds taken; finished records are skipped on rerun)
        verdicts.jsonl         (one line per record, in sample order, same format as the other annotators)

The system message is prompt.md unchanged; the user message is the record rendered exactly as in
../batches. Temperature 0. A response is retried (up to 3 times) when it is not valid JSON Lines or
its pair IDs do not match the record.
"""
import argparse
import importlib.util
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
ANNOTATOR = HERE.name
MODEL = 'openai/gpt-oss-120b'
URL = 'http://localhost:8011/v1/chat/completions'
ATTEMPTS = 3
MAX_TOKENS = 16000

# Same parsing and record rendering as the DeepSeek annotator.
def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

make_sample = _load('make_sample', HERE.parent / 'make_sample.py')
parse = _load('deepseek_run', HERE.parent / 'deepseek-v4-flash-0731' / 'run_judge.py').parse


def judge(record, system, effort):
    path = HERE / 'raw' / f"{record['id']}.json"
    if path.exists():
        return record['id'], 'cached', None
    error = None
    for attempt in range(ATTEMPTS):
        start = time.time()
        try:
            r = requests.post(URL, timeout=3600, json={
                'model': MODEL, 'temperature': 0, 'max_tokens': MAX_TOKENS, 'reasoning_effort': effort,
                'messages': [{'role': 'system', 'content': system},
                             {'role': 'user', 'content': make_sample.render(record)}]})
            r.raise_for_status()
            body = r.json()
            parse(body['choices'][0]['message']['content'] or '', record)
            seconds = round(time.time() - start, 1)
            path.write_text(json.dumps({'record_id': record['id'], 'attempt': attempt + 1, 'effort': effort,
                                        'seconds': seconds, 'response': body}, indent=1))
            return record['id'], 'ok', body.get('usage', {})
        except (requests.RequestException, ValueError, KeyError, json.JSONDecodeError) as e:
            error = f'{type(e).__name__}: {e}'
    return record['id'], f'failed: {error[:300]}', None


def write_verdicts(records):
    n = 0
    with open(HERE / 'verdicts.jsonl', 'w') as f:
        for r in records:
            path = HERE / 'raw' / f"{r['id']}.json"
            if not path.exists():
                continue
            body = json.loads(path.read_text())['response']
            f.write(json.dumps({'record_id': r['id'], 'cve_id': r['cve_id'], 'source': r['source'],
                                'language': r['language'], 'annotator': ANNOTATOR,
                                'verdicts': parse(body['choices'][0]['message']['content'], r)}) + '\n')
            n += 1
    print(f'{n} records -> {HERE / "verdicts.jsonl"}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=None)
    ap.add_argument('--workers', type=int, default=64)
    ap.add_argument('--effort', default='medium', choices=['low', 'medium', 'high'])
    args = ap.parse_args()
    system = (HERE.parent / 'prompt.md').read_text()
    records = json.loads((HERE.parent / 'sample_records.json').read_text())
    todo = records[:args.limit] if args.limit else records
    (HERE / 'raw').mkdir(exist_ok=True)
    start, done, tokens, failed = time.time(), 0, 0, []
    with ThreadPoolExecutor(args.workers) as pool:
        futures = [pool.submit(judge, r, system, args.effort) for r in todo]
        for n, fut in enumerate(as_completed(futures), 1):
            rid, status, usage = fut.result()
            if status == 'ok':
                done += 1
                tokens += usage.get('completion_tokens', 0)
            elif status != 'cached':
                failed.append(rid)
                print(rid, status, flush=True)
            if n % 25 == 0 or n == len(futures):
                minutes = (time.time() - start) / 60
                print(f'{n}/{len(futures)} done; {done} judged this run in {minutes:.1f} min '
                      f'({done / max(minutes, 1e-9):.1f} records/min, {tokens / max(done, 1):.0f} output tokens/record)',
                      flush=True)
    print(f'not done: {len(failed)} {failed[:20]}')
    write_verdicts(records)


if __name__ == '__main__':
    main()
