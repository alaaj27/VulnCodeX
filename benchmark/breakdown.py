"""Judge scores of the main runs by question topic, language and source.

Usage:  python3 benchmark/breakdown.py [--split cve]
Reads:  data/splits/<split>.json (test ids; vulncodex.load_split), <model>/judged_<split>.jsonl for the four main models;
        topic rules from vulncodex/topics.py
Writes: breakdown_<split>.json  (score_% and pairs per group and model; correct = 1, partially = 0.5)
"""
import argparse
import collections
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from vulncodex import load_split  # noqa: E402
from vulncodex.topics import topic_of  # noqa: E402

MODELS = ['foundation-sec-8b-instruct', 'qwen2.5-coder-7b-instruct', 'opencoder-8b-instruct', 'gemma-4-31b-it']
LABELS = {'correct': 1.0, 'partially_correct': 0.5, 'incorrect': 0.0}

ap = argparse.ArgumentParser()
ap.add_argument('--split', default='cve')
args = ap.parse_args()
records = load_split(args.split, 'test')
info = {}
for r in records:
    for k, q in enumerate(r['conversations'][0::2], 1):
        info[f"{r['id']}#{k}"] = {'topic': topic_of(q['value'].replace('<code_sequence>', '')), 'language': r['language'],
                                  'source': 'Big-Vul' if r['id'].startswith('msr') else 'CVEfixes'}
out = {}
for by in ('topic', 'language', 'source'):
    out[by] = collections.defaultdict(dict)
    for m in MODELS:
        groups = collections.defaultdict(list)
        for line in (HERE / m / f'judged_{args.split}.jsonl').read_text().splitlines():
            v = json.loads(line)
            groups[info[v['pair_id']][by]].append(LABELS[v['correctness']])
        for g, s in groups.items():
            out[by][g][m] = {'pairs': len(s), 'score_%': round(100 * sum(s) / len(s), 1)}
(HERE / f'breakdown_{args.split}.json').write_text(json.dumps(out, indent=1) + '\n')
for by in ('topic', 'language', 'source'):
    print('==', by)
    for g, row in sorted(out[by].items(), key=lambda kv: -next(iter(kv[1].values()))['pairs']):
        print(f"  {g:22s} n={next(iter(row.values()))['pairs']:5d}  " + '  '.join(f"{m.split('-')[0][:8]:8s} {row[m]['score_%']:5.1f}" for m in MODELS))
