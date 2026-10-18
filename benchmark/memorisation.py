"""B6: do models score lower on recent CVEs than on old ones? (a memorisation signal)

Usage:  python3 benchmark/memorisation.py [--split cve]
Reads:  data/splits/<split>.json (test ids; vulncodex.load_split), <model>/judged_<split>.jsonl for the four main models
Writes: benchmark/memorisation_<split>.json
        figures/out/memorisation_forest.tex  (pgfplots forest plot; not used by the paper, which uses Fig4 option 3)

Design. Every CVE in the dataset predates every model's training cut-off, so a before/after-cut-off
comparison is impossible; instead we compare OLD CVEs (year <= OLD_MAX), which have been discussed
online for longer, with RECENT ones (year >= RECENT_MIN). Only CVEfixes records are used: Big-Vul ends
in 2019 and scores higher, so mixing sources would confound year with source.
Two estimates per model, both "recent minus old" judge score in points (correct = 1, partial = 0.5):
  raw             difference of the mean pair scores of the two groups;
  topic-adjusted  per-topic differences, weighted by each topic's share of all questions in both groups
                  (topics present in both groups only), so a shift in question mix cannot drive it.
95% intervals: bootstrap over records, resampling the two groups separately (BOOTSTRAP draws, seed 0).
"""
import argparse
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

MODELS = [('foundation-sec-8b-instruct', 'Foundation-Sec-8B'), ('qwen2.5-coder-7b-instruct', 'Qwen2.5-Coder-7B'),
          ('opencoder-8b-instruct', 'OpenCoder-8B'), ('gemma-4-31b-it', 'Gemma-4-31B')]
LABELS = {'correct': 1.0, 'partially_correct': 0.5, 'incorrect': 0.0}
OLD_MAX, RECENT_MIN = 2015, 2022
BOOTSTRAP = 2000


def raw_diff(old, recent):
    mean = lambda recs: sum(s for r in recs for _, s in r) / sum(len(r) for r in recs)
    return 100 * (mean(recent) - mean(old))


def adjusted_diff(old, recent):
    by = {g: collections.defaultdict(list) for g in ('old', 'recent')}
    for g, recs in (('old', old), ('recent', recent)):
        for r in recs:
            for topic, s in r:
                by[g][topic].append(s)
    topics = [t for t in by['old'] if t in by['recent']]
    weight = {t: len(by['old'][t]) + len(by['recent'][t]) for t in topics}
    total = sum(weight.values())
    return 100 * sum(weight[t] / total * (sum(by['recent'][t]) / len(by['recent'][t]) - sum(by['old'][t]) / len(by['old'][t]))
                     for t in topics)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--split', default='cve')
    args = ap.parse_args()
    records = load_split(args.split, 'test')
    year = {r['id']: int(r['cve_id'].split('-')[1]) for r in records}
    topic = {f"{r['id']}#{k}": topic_of(q['value'].replace('<code_sequence>', ''))
             for r in records for k, q in enumerate(r['conversations'][0::2], 1)}
    keep = {r['id'] for r in records if r['id'].startswith('cvefixes')}
    out = {'old_max_year': OLD_MAX, 'recent_min_year': RECENT_MIN, 'source': 'CVEfixes only', 'models': {}}
    rng = random.Random(0)
    for key, name in MODELS:
        per_record = collections.defaultdict(list)
        for line in (HERE / key / f'judged_{args.split}.jsonl').read_text().splitlines():
            v = json.loads(line)
            rid = v['pair_id'].split('#')[0]
            if rid in keep:
                per_record[rid].append((topic[v['pair_id']], LABELS[v['correctness']]))
        old = [p for rid, p in per_record.items() if year[rid] <= OLD_MAX]
        recent = [p for rid, p in per_record.items() if year[rid] >= RECENT_MIN]
        result = {'old_records': len(old), 'recent_records': len(recent),
                  'old_score_%': round(100 * sum(s for r in old for _, s in r) / sum(len(r) for r in old), 1),
                  'recent_score_%': round(100 * sum(s for r in recent for _, s in r) / sum(len(r) for r in recent), 1)}
        for label, fn in (('raw', raw_diff), ('topic_adjusted', adjusted_diff)):
            boot = sorted(fn(rng.choices(old, k=len(old)), rng.choices(recent, k=len(recent))) for _ in range(BOOTSTRAP))
            result[label] = {'diff_points': round(fn(old, recent), 1),
                             'ci95': [round(boot[int(0.025 * BOOTSTRAP)], 1), round(boot[int(0.975 * BOOTSTRAP)], 1)]}
        out['models'][name] = result
        print(name, result)
    (HERE / f'memorisation_{args.split}.json').write_text(json.dumps(out, indent=1) + '\n')

    # ---- forest plot: one row per model; filled circle = raw, open diamond = topic-adjusted
    rows = list(out['models'].items())
    lo = min(r[k]['ci95'][0] for _, r in rows for k in ('raw', 'topic_adjusted'))
    hi = max(r[k]['ci95'][1] for _, r in rows for k in ('raw', 'topic_adjusted'))
    xmin, xmax = min(-2, 2 * int(lo / 2) - 2), max(2, 2 * int(hi / 2) + 2)

    def series(kind, offset):
        pts = []
        for i, (_, r) in enumerate(rows):
            y = len(rows) - i + offset
            d, (a, b) = r[kind]['diff_points'], r[kind]['ci95']
            pts.append(f'({d},{y}) -= ({d - a:.1f},0) += ({b - d:.1f},0)')
        return ' '.join(pts)

    yticks = ','.join(str(len(rows) - i) for i in range(len(rows)))
    ylabels = ','.join(n for n, _ in rows)
    tex = rf"""% Requires: \usepackage{{pgfplots}}
% Generated by benchmark/memorisation.py -- do not edit by hand.
\begin{{figure}}[t]
\centering
\definecolor{{fpblue}}{{HTML}}{{2A78D6}}
\definecolor{{fporange}}{{HTML}}{{EB6834}}
\begin{{tikzpicture}}
\begin{{axis}}[
  scale only axis, width=0.62\columnwidth, height=3.4cm,
  xmin={xmin}, xmax={xmax}, ymin=0.4, ymax={len(rows) + 0.6},
  ytick={{{yticks}}}, yticklabels={{{ylabels}}},
  y tick label style={{font=\footnotesize}}, x tick label style={{font=\footnotesize}},
  xlabel={{\footnotesize Recent minus old CVEs (judge score, points)}},
  xmajorgrids, grid style={{gray!25}}, axis line style={{gray!70}}, tick style={{gray!70}},
  legend style={{font=\scriptsize, at={{(0.5,-0.30)}}, anchor=north, draw=none}}, legend columns=2,
  legend cell align=left,
]
\addplot[gray!70, dashed, forget plot] coordinates {{(0,0.4) (0,{len(rows) + 0.6})}};
\addplot[only marks, mark=*, mark size=2.2pt, color=fpblue,
         error bars/.cd, x dir=both, x explicit, error bar style={{line width=0.8pt}}]
  coordinates {{{series('raw', 0.12)}}};
\addlegendentry{{Raw}}
\addplot[only marks, mark=diamond, mark size=2.8pt, color=fporange, mark options={{fill=white}},
         error bars/.cd, x dir=both, x explicit, error bar style={{line width=0.8pt}}]
  coordinates {{{series('topic_adjusted', -0.12)}}};
\addlegendentry{{Topic-adjusted}}
\end{{axis}}
\end{{tikzpicture}}
\caption{{Judge score on recent CVEs (2022--2024, {rows[0][1]['recent_records']} records) minus old CVEs ($\leq$2015,
{rows[0][1]['old_records']} records), CVEfixes test records only. Bars are 95\% bootstrap intervals over records; the
topic-adjusted estimate compares the two groups within each question topic. Values below zero mean a model
does worse on recent vulnerabilities.}}
\label{{fig:memorisation}}
\end{{figure}}
"""
    (ROOT / 'figures' / 'out' / 'memorisation_forest.tex').write_text(tex)


if __name__ == '__main__':
    main()
