"""Judge every sampled record with DeepSeek V4 Flash through OpenRouter, one request per record.

Usage:  OPENROUTER_API_KEY=... python hallucination_analysis/deepseek-v4-flash-0731/run_judge.py
            [--limit N] [--workers 16] [--budget 10]
Reads:  ../sample_records.json, ../prompt.md
Writes: raw/<record id>.json   (full API response, one per record; finished records are skipped on rerun)
        verdicts.jsonl         (one line per record, in sample order, same format as claude-opus-5-5)
        cost.json              (tokens and dollars spent)

The system message is prompt.md unchanged; the user message is the record rendered exactly as in
../batches. Temperature 0. A response is retried (up to 3 times) when it is not valid JSON Lines or
its pair IDs do not match the record. The run stops submitting once the spend reaches --budget.
"""
import argparse
import importlib.util
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
ANNOTATOR = HERE.name
MODEL = 'deepseek/deepseek-v4-flash-0731'
# MODEL = 'google/gemma-4-31b-it:free'
URL = 'https://openrouter.ai/api/v1/chat/completions'
SUPPORT = {'supported', 'partly_supported', 'unsupported', 'contradicted'}
ERRORS = {'wrong_location', 'invented_identifier', 'wrong_vulnerability_type', 'wrong_mechanism',
          'wrong_impact', 'wrong_version_or_product', 'unfounded_severity', 'inapplicable_fix',
          'generic_or_evasive', 'other'}
ATTEMPTS = 3

spec = importlib.util.spec_from_file_location('make_sample', HERE.parent / 'make_sample.py')
make_sample = importlib.util.module_from_spec(spec)
spec.loader.exec_module(make_sample)

lock = threading.Lock()
spent = {'requests': 0, 'prompt_tokens': 0, 'completion_tokens': 0, 'reasoning_tokens': 0, 'cost_usd': 0.0}


def parse(text, record):
    """Return the record's pair verdicts from a response, or raise ValueError."""
    text = re.sub(r'^```\w*\s*|\s*```$', '', text.strip())
    rows = [json.loads(line) for line in text.splitlines() if line.strip().startswith('{')]
    expected = [p['pair_id'] for p in record['pairs']]
    if [v.get('pair_id') for v in rows] != expected:
        raise ValueError(f'pair IDs {[v.get("pair_id") for v in rows]} != {expected}')
    out = []
    for v in rows:
        if v.get('support') not in SUPPORT or not isinstance(v.get('question_relevant'), bool) \
                or not isinstance(v.get('answerable_from_code'), bool):
            raise ValueError(f'bad labels in {v}')
        # Normalise the error type the same way the checker requires: null exactly for supported pairs.
        err = v.get('error_type')
        if v['support'] == 'supported':
            err = None
        elif err not in ERRORS:
            err = 'other'
        out.append({'pair_id': v['pair_id'], 'question_relevant': v['question_relevant'], 'support': v['support'],
                    'answerable_from_code': v['answerable_from_code'], 'error_type': err,
                    'reason': str(v.get('reason', ''))})
    return out


def judge(record, system, key, budget):
    path = HERE / 'raw' / f"{record['id']}.json"
    if path.exists():
        return record['id'], 'cached'
    error = None
    for attempt in range(ATTEMPTS):
        with lock:
            if spent['cost_usd'] >= budget:
                return record['id'], 'budget reached'
        try:
            r = requests.post(URL, timeout=600, headers={'Authorization': f'Bearer {key}'}, json={
                'model': MODEL, 'temperature': 0, 'usage': {'include': True},
                'messages': [{'role': 'system', 'content': system},
                             {'role': 'user', 'content': make_sample.render(record)}]})
            if r.status_code == 429 or r.status_code >= 500:
                raise RuntimeError(f'HTTP {r.status_code}: {r.text[:200]}')
            r.raise_for_status()
            body = r.json()
            usage = body.get('usage', {})
            with lock:
                spent['requests'] += 1
                spent['prompt_tokens'] += usage.get('prompt_tokens', 0)
                spent['completion_tokens'] += usage.get('completion_tokens', 0)
                spent['reasoning_tokens'] += (usage.get('completion_tokens_details') or {}).get('reasoning_tokens') or 0
                spent['cost_usd'] += usage.get('cost') or 0
            parse(body['choices'][0]['message']['content'] or '', record)
            path.write_text(json.dumps({'record_id': record['id'], 'attempt': attempt + 1, 'response': body}, indent=1))
            return record['id'], 'ok'
        except (requests.RequestException, RuntimeError, ValueError, KeyError, json.JSONDecodeError) as e:
            error = f'{type(e).__name__}: {e}'
            time.sleep(5 * (attempt + 1))
    return record['id'], f'failed: {error[:300]}'


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
    ap.add_argument('--workers', type=int, default=16)
    ap.add_argument('--budget', type=float, default=10.0)
    args = ap.parse_args()
    key = os.environ.get('OPENROUTER_API_KEY')
    if not key:
        raise SystemExit('Set OPENROUTER_API_KEY to an OpenRouter API key')
    system = (HERE.parent / 'prompt.md').read_text()
    records = json.loads((HERE.parent / 'sample_records.json').read_text())
    todo = records[:args.limit] if args.limit else records
    (HERE / 'raw').mkdir(exist_ok=True)
    status = {}
    with ThreadPoolExecutor(args.workers) as pool:
        futures = [pool.submit(judge, r, system, key, args.budget) for r in todo]
        for n, fut in enumerate(as_completed(futures), 1):
            rid, s = fut.result()
            status[rid] = s
            if s not in ('ok', 'cached'):
                print(rid, s, flush=True)
            if n % 50 == 0 or n == len(futures):
                print(f'{n}/{len(futures)} done, ${spent["cost_usd"]:.3f} spent this run', flush=True)
    cost_path = HERE / 'cost.json'
    total = json.loads(cost_path.read_text()) if cost_path.exists() else {k: 0 for k in spent}
    for k in spent:
        total[k] += spent[k]
    cost_path.write_text(json.dumps(total, indent=1) + '\n')
    failed = sorted(k for k, s in status.items() if s not in ('ok', 'cached'))
    print(f'this run: {spent}; total: {total}; not done: {len(failed)}')
    write_verdicts(records)


if __name__ == '__main__':
    main()
