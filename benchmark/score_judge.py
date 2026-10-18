"""Grade every benchmarked model's answers with gpt-oss-120b served locally by vLLM.

Server:  vllm serve openai/gpt-oss-120b \
             --port 8011 --max-model-len 32768 --gpu-memory-utilization 0.92
Usage:   python benchmark/score_judge.py [--split cve] [--models a b:variant ...]
Reads:   judge_prompt.md, data/splits/<split>.json (test ids; vulncodex.load_split), <model>/answers_<split>[_<variant>].jsonl
Writes:  <model>/judge[_<variant>]/<record id>.json   full judge response (finished records are skipped)
         <model>/judged_<split>[_<variant>].jsonl     one line per pair: correctness, reference_wrong, reason
         judge_<split>.json               summary per model; ablation variants are keyed "<model>:<variant>"

One request per record and model: the system message is judge_prompt.md, the user message gives the
CVE description, the code (shortened as in the main prompts, whatever the model saw), and each question with its reference
and model answer. Temperature 0, medium reasoning effort, up to 3 attempts when the output is not
valid JSON Lines with the right pair IDs. Score: correct = 1, partially correct = 0.5, incorrect = 0.
"""
import argparse
import collections
import json
import sys
import random
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from vulncodex import load_split  # noqa: E402
URL = 'http://localhost:8011/v1/chat/completions'
JUDGE = 'openai/gpt-oss-120b'
LABELS = {'correct': 1.0, 'partially_correct': 0.5, 'incorrect': 0.0}
PLACEHOLDER = '<code_sequence>'
BOOTSTRAP = 1000


def code_as_seen(prompt):
    return prompt.split('```\n', 1)[1].rsplit('\n```', 1)[0]


def render(record, code, answers):
    lines = ['CVE DESCRIPTION:', record['description'], '', 'CODE:', '```', code, '```', '', 'QUESTIONS:']
    for k, (q, a) in enumerate(zip(record['conversations'][0::2], record['conversations'][1::2]), 1):
        pid = f"{record['id']}#{k}"
        lines += [f'[{pid}]', 'Question: ' + q['value'].replace(PLACEHOLDER, '').strip(),
                  'Reference answer: ' + a['value'].strip(),
                  'Model answer: ' + (answers.get(pid) or '(no answer)'), '']
    return '\n'.join(lines)


def parse(text, pair_ids):
    text = re.sub(r'^```\w*\s*|\s*```$', '', (text or '').strip())
    rows = [json.loads(l) for l in text.splitlines() if l.strip().startswith('{')]
    if [r.get('pair_id') for r in rows] != pair_ids:
        raise ValueError('pair ids')
    for r in rows:
        if r.get('correctness') not in LABELS or not isinstance(r.get('reference_wrong'), bool):
            raise ValueError(f'labels {r}')
    return [{'pair_id': r['pair_id'], 'correctness': r['correctness'], 'reference_wrong': r['reference_wrong'],
             'reason': str(r.get('reason', ''))} for r in rows]


def judge(record, code, answers, judge_dir, system):
    path = judge_dir / f"{record['id']}.json"
    if path.exists():
        return 'cached'
    pair_ids = [f"{record['id']}#{k}" for k in range(1, len(record['conversations']) // 2 + 1)]
    for attempt in range(3):
        try:
            r = requests.post(URL, timeout=3600, json={
                'model': JUDGE, 'temperature': 0, 'max_tokens': 16000, 'reasoning_effort': 'medium',
                'messages': [{'role': 'system', 'content': system},
                             {'role': 'user', 'content': render(record, code, answers)}]})
            r.raise_for_status()
            body = r.json()
            parse(body['choices'][0]['message']['content'], pair_ids)
            path.write_text(json.dumps({'record_id': record['id'], 'attempt': attempt + 1, 'response': body}))
            return 'ok'
        except (requests.RequestException, ValueError, KeyError, json.JSONDecodeError) as e:
            error = e
    return f'failed: {str(error)[:200]}'


def summarise(rows, record_of, rng):
    scores = [LABELS[r['correctness']] for r in rows]
    by_record = collections.defaultdict(list)
    for r, s in zip(rows, scores):
        by_record[record_of[r['pair_id']]].append(s)
    keys = list(by_record)
    boot = sorted(sum(sum(by_record[k]) for k in sample) / sum(len(by_record[k]) for k in sample)
                  for sample in (rng.choices(keys, k=len(keys)) for _ in range(BOOTSTRAP)))
    count = collections.Counter(r['correctness'] for r in rows)
    return {'pairs': len(rows), 'score_%': round(100 * sum(scores) / len(scores), 1),
            'score_95ci': [round(100 * boot[int(0.025 * BOOTSTRAP)], 1), round(100 * boot[int(0.975 * BOOTSTRAP)], 1)],
            **{f'{k}_%': round(100 * count[k] / len(rows), 1) for k in LABELS},
            'reference_wrong_%': round(100 * sum(r['reference_wrong'] for r in rows) / len(rows), 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--split', default='cve')
    ap.add_argument('--models', nargs='*')
    ap.add_argument('--workers', type=int, default=32)
    args = ap.parse_args()
    system = (HERE / 'judge_prompt.md').read_text()
    records = load_split(args.split, 'test')
    code = {json.loads(l)['record_id']: code_as_seen(json.loads(l)['prompt'])
            for l in (HERE / f'prompts_{args.split}.jsonl').read_text().splitlines()}
    record_of = {f"{r['id']}#{k}": r['id'] for r in records for k in range(1, len(r['conversations']) // 2 + 1)}
    models = args.models or sorted(
        p.parent.name + (':' + p.stem[len(f'answers_{args.split}_'):] if p.stem != f'answers_{args.split}' else '')
        for p in HERE.glob(f'*/answers_{args.split}*.jsonl'))
    summary_path = HERE / f'judge_{args.split}.json'
    summary = json.loads(summary_path.read_text()) if summary_path.exists() else {}
    for model in models:
        name, _, variant = model.partition(':')
        suffix = f'_{variant}' if variant else ''
        out_dir = HERE / name
        judge_dir = out_dir / f'judge{suffix}'
        judge_dir.mkdir(exist_ok=True)
        answers = {json.loads(l)['pair_id']: json.loads(l)['answer']
                   for l in (out_dir / f'answers_{args.split}{suffix}.jsonl').read_text().splitlines()}
        # Only the records this run answered (an ablation run covers the ablation subset only).
        todo = [r for r in records if f"{r['id']}#1" in answers]
        with ThreadPoolExecutor(args.workers) as pool:
            status = list(pool.map(lambda r: judge(r, code[r['id']], answers, judge_dir, system), todo))
        failed = [r['id'] for r, s in zip(todo, status) if s.startswith('failed')]
        rows = []
        with open(out_dir / f'judged_{args.split}{suffix}.jsonl', 'w') as f:
            for r in todo:
                path = judge_dir / f"{r['id']}.json"
                if not path.exists():
                    continue
                pair_ids = [f"{r['id']}#{k}" for k in range(1, len(r['conversations']) // 2 + 1)]
                for row in parse(json.loads(path.read_text())['response']['choices'][0]['message']['content'], pair_ids):
                    f.write(json.dumps(row) + '\n')
                    rows.append(row)
        summary[model] = {**summarise(rows, record_of, random.Random(0)), 'records_not_judged': failed}
        summary_path.write_text(json.dumps(summary, indent=1) + '\n')
        print(model, summary[model], flush=True)


if __name__ == '__main__':
    main()
