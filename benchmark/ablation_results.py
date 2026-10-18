"""Score the input ablation: one model, the same records, four inputs.

Usage:  python benchmark/ablation_results.py [--model gemma-4-31b-it]
Reads:  ablation_records.json, <model>/judged_cve[_<setting>].jsonl, metrics_cve.json
Writes: benchmark/ablation_results.json

The settings are code (the main benchmark run, restricted to the ablation records), no_code, code_desc
and desc_only. LLM-as-judge score = correct 1, partially correct 0.5. Only records graded in every
setting are used (999 of the 1,000). 95% intervals are bootstraps over records (2,000 draws, seed 0);
differences to the code-only setting are paired by record. ablation_model.txt records why the model
was chosen.
"""
import argparse
import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
LABELS = {'correct': 1.0, 'partially_correct': 0.5, 'incorrect': 0.0}
SETTINGS = ['code', 'no_code', 'code_desc', 'desc_only']
BOOTSTRAP = 2000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--model', default='gemma-4-31b-it')
    model = ap.parse_args().model
    subset = set(json.loads((HERE / 'ablation_records.json').read_text())['records'])
    per = {}
    for s in SETTINGS:
        path = HERE / model / ('judged_cve.jsonl' if s == 'code' else f'judged_cve_{s}.jsonl')
        recs = {}
        for line in path.read_text().splitlines():
            v = json.loads(line)
            rid = v['pair_id'].split('#')[0]
            if rid in subset:
                recs.setdefault(rid, []).append(LABELS[v['correctness']])
        per[s] = recs
    ids = sorted(set.intersection(*(set(r) for r in per.values())))
    rng = random.Random(0)

    def score(s, sample):
        return 100 * sum(x for r in sample for x in per[s][r]) / sum(len(per[s][r]) for r in sample)

    metrics = json.loads((HERE / 'metrics_cve.json').read_text())
    out = {'model': model, 'records': len(ids), 'settings': {}}
    for s in SETTINGS:
        boot = sorted(score(s, rng.choices(ids, k=len(ids))) for _ in range(BOOTSTRAP))
        diff = sorted(score(s, smp) - score('code', smp) for smp in (rng.choices(ids, k=len(ids)) for _ in range(BOOTSTRAP)))
        m = metrics.get(f'{model}:{s}', {})
        out['settings'][s] = {'judge_%': round(score(s, ids), 1),
                              'judge_95ci': [round(boot[int(0.025 * BOOTSTRAP)], 1), round(boot[int(0.975 * BOOTSTRAP)], 1)],
                              'diff_vs_code': round(score(s, ids) - score('code', ids), 1),
                              'diff_95ci': [round(diff[int(0.025 * BOOTSTRAP)], 1), round(diff[int(0.975 * BOOTSTRAP)], 1)],
                              'rougeL': m.get('rougeL_f'), 'bleu4': m.get('bleu4'), 'cider': m.get('cider_d')}
    (HERE / 'ablation_results.json').write_text(json.dumps(out, indent=1) + '\n')
    for s, v in out['settings'].items():
        print(f"{s:10s} {v['judge_%']:5.1f} {v['judge_95ci']}  vs code {v['diff_vs_code']:+5.1f} {v['diff_95ci']}")


if __name__ == '__main__':
    main()
