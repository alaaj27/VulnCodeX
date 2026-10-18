"""Ask one model (served by vLLM on PORT) every benchmark prompt; one request per record.

Usage:  python benchmark/run_model.py --name <folder> --model <served model id> [--split cve] [--variant code]
Reads:  prompts_<split>[_<variant>].jsonl  (see build_prompts.py; no suffix for the main variant "code")
Writes: <name>/raw[_<variant>]/<record id>.json   full response (finished records are skipped on rerun)
        <name>/answers_<split>[_<variant>].jsonl  one line per pair: pair_id, answer ("" if the reply had none)
        <name>/run_<split>[_<variant>].json       settings, timing, how many answers were parsed

Temperature 0, at most MAX_TOKENS output tokens, thinking disabled where the chat template supports it.
The reply is split on lines that start with "<number>." or "<number>)"; an answer runs to the next
numbered line. Missing numbers give empty answers, which score zero.
"""
import argparse
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
PORT = 8011
MAX_TOKENS = 1500
NUMBERED = re.compile(r'^\s*(?:\*\*)?(\d{1,2})[.)](?:\*\*)?\s*(.*)$')


def split_answers(text, n):
    answers, current = {}, None
    for line in (text or '').splitlines():
        m = NUMBERED.match(line)
        if m and 1 <= int(m.group(1)) <= n and int(m.group(1)) not in answers:
            current = int(m.group(1))
            answers[current] = m.group(2).strip()
        elif current is not None and line.strip():
            answers[current] += ' ' + line.strip()
    return [answers.get(k, '').strip() for k in range(1, n + 1)]


def ask(item, raw_dir, model):
    path = raw_dir / f"{item['record_id']}.json"
    if path.exists():
        return
    for attempt in range(3):
        try:
            r = requests.post(f'http://localhost:{PORT}/v1/chat/completions', timeout=1800, json={
                'model': model, 'temperature': 0, 'max_tokens': MAX_TOKENS,
                'chat_template_kwargs': {'enable_thinking': False},
                'messages': [{'role': 'user', 'content': item['prompt']}]})
            r.raise_for_status()
            path.write_text(json.dumps({'record_id': item['record_id'], 'response': r.json()}))
            return
        except requests.RequestException as e:
            error = e
            time.sleep(10)
    print('failed', item['record_id'], str(error)[:200], flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--name', required=True)
    ap.add_argument('--model', required=True)
    ap.add_argument('--split', default='cve')
    ap.add_argument('--workers', type=int, default=64)
    ap.add_argument('--variant', default='code')
    args = ap.parse_args()
    suffix = '' if args.variant == 'code' else f'_{args.variant}'
    out_dir = HERE / args.name
    raw_dir = out_dir / f'raw{suffix}'
    raw_dir.mkdir(parents=True, exist_ok=True)
    items = [json.loads(l) for l in (HERE / f'prompts_{args.split}{suffix}.jsonl').read_text().splitlines()]
    start = time.time()
    with ThreadPoolExecutor(args.workers) as pool:
        for n, _ in enumerate(pool.map(lambda it: ask(it, raw_dir, args.model), items), 1):
            if n % 250 == 0:
                print(f'{n}/{len(items)} records, {(time.time() - start) / 60:.1f} min', flush=True)
    missing = [it['record_id'] for it in items if not (raw_dir / f"{it['record_id']}.json").exists()]
    if missing:
        # Leave no run file, so the drivers do not treat the model as done (or delete its weights).
        raise SystemExit(f'{len(missing)} records have no response (first: {missing[:3]}); rerun to retry them')
    pairs, empty, finish = 0, 0, {}
    with open(out_dir / f'answers_{args.split}{suffix}.jsonl', 'w') as f:
        for it in items:
            path = raw_dir / f"{it['record_id']}.json"
            body = json.loads(path.read_text())['response'] if path.exists() else {}
            choice = (body.get('choices') or [{}])[0]
            finish[choice.get('finish_reason')] = finish.get(choice.get('finish_reason'), 0) + 1
            answers = split_answers((choice.get('message') or {}).get('content'), len(it['pair_ids']))
            for pid, a in zip(it['pair_ids'], answers):
                f.write(json.dumps({'pair_id': pid, 'answer': a}) + '\n')
                pairs += 1
                empty += not a
    run = {'model': args.model, 'split': args.split, 'variant': args.variant, 'records': len(items), 'pairs': pairs,
           'empty_answers': empty, 'empty_answers_%': round(100 * empty / pairs, 2),
           'finish_reasons': finish, 'minutes_this_run': round((time.time() - start) / 60, 1),
           'max_tokens': MAX_TOKENS, 'temperature': 0}
    (out_dir / f'run_{args.split}{suffix}.json').write_text(json.dumps(run, indent=1) + '\n')
    print(json.dumps(run))


if __name__ == '__main__':
    main()
