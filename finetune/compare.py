"""Fine-tuned vs zero-shot Qwen2.5-Coder-7B on the code-only benchmark (LLM-as-judge), paired by question.

Usage:  python finetune/compare.py
Reads:  data/splits/cve.json (test ids; vulncodex.load_split), benchmark/<model>/judged_cve.jsonl for both models
Writes: finetune/comparison_cve.json

Only questions graded for both models are compared. Score: correct 1, partially correct 0.5. The 95%
intervals of the difference are paired bootstraps over records (2,000 draws, seed 0): each draw
resamples records and recomputes both models' scores on the same questions. Breakdowns: question topic
(topic rules of make_dataset_stats.py), CVE year (old <= 2015, recent >= 2022, CVEfixes records only, as
in the memorisation analysis) and source.
"""
import collections
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from vulncodex import load_split  # noqa: E402
from vulncodex.topics import topic_of  # noqa: E402

B = ROOT / 'benchmark'
BASE, TUNED = 'qwen2.5-coder-7b-instruct', 'qwen2.5-coder-7b-vulncodex'
LABELS = {'correct': 1.0, 'partially_correct': 0.5, 'incorrect': 0.0}
BOOTSTRAP = 2000


def load(model):
    return {v['pair_id']: LABELS[v['correctness']]
            for v in map(json.loads, (B / model / 'judged_cve.jsonl').read_text().splitlines())}


def compare(pairs, base, tuned, rng):
    by_rec = collections.defaultdict(list)
    for p in pairs:
        by_rec[p.split('#')[0]].append(p)
    recs = sorted(by_rec)

    def scores(sample):
        ps = [p for r in sample for p in by_rec[r]]
        return 100 * sum(base[p] for p in ps) / len(ps), 100 * sum(tuned[p] for p in ps) / len(ps)

    b, t = scores(recs)
    diffs = sorted(t2 - b2 for b2, t2 in (scores(rng.choices(recs, k=len(recs))) for _ in range(BOOTSTRAP)))
    return {'questions': len(pairs), 'records': len(recs), 'zero_shot': round(b, 1), 'fine_tuned': round(t, 1),
            'difference': round(t - b, 1),
            'difference_95ci': [round(diffs[int(0.025 * BOOTSTRAP)], 1), round(diffs[int(0.975 * BOOTSTRAP)], 1)]}


def main():
    records = {r['id']: r for r in load_split('cve', 'test')}
    base, tuned = load(BASE), load(TUNED)
    pairs = sorted(p for p in tuned if p in base)
    topic = {p: topic_of(records[p.split('#')[0]]['conversations'][0::2][int(p.split('#')[1]) - 1]['value']
                         .replace('<code_sequence>', '')) for p in pairs}
    year = {rid: int(r['cve_id'].split('-')[1]) for rid, r in records.items()}
    rng = random.Random(0)
    out = {'all': compare(pairs, base, tuned, rng), 'by_topic': {}, 'by_period_cvefixes': {}, 'by_source': {}}
    for t in sorted(set(topic.values()), key=lambda t: -sum(1 for p in pairs if topic[p] == t)):
        out['by_topic'][t] = compare([p for p in pairs if topic[p] == t], base, tuned, rng)
    for name, keep in [('old (<=2015)', lambda y: y <= 2015), ('recent (>=2022)', lambda y: y >= 2022)]:
        sel = [p for p in pairs if p.startswith('cvefixes') and keep(year[p.split('#')[0]])]
        out['by_period_cvefixes'][name] = compare(sel, base, tuned, rng)
    for src in ('cvefixes', 'msr'):
        out['by_source']['Big-Vul' if src == 'msr' else 'CVEfixes'] = compare([p for p in pairs if p.startswith(src)], base, tuned, rng)
    (HERE / 'comparison_cve.json').write_text(json.dumps(out, indent=1) + '\n')
    a = out['all']
    print(f"all: {a['zero_shot']} -> {a['fine_tuned']} ({a['difference']:+} {a['difference_95ci']}) on {a['questions']} questions")
    for group in ('by_topic', 'by_period_cvefixes', 'by_source'):
        for k, v in out[group].items():
            print(f"  {k:22} n={v['questions']:5}  {v['zero_shot']:5} -> {v['fine_tuned']:5}  {v['difference']:+5} {v['difference_95ci']}")


if __name__ == '__main__':
    main()
