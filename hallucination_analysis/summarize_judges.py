"""Combine all annotators into majority-vote labels and agreement statistics.

Usage:  python hallucination_analysis/summarize_judges.py claude-opus-5-5 deepseek-v4-flash-0731 gpt-oss-120b
Reads:  sample_records.json, <annotator>/verdicts.jsonl for each annotator named
Writes: summary.json             (rates per judge and by majority vote, pairwise and Fleiss kappa)
        majority_verdicts.jsonl  (one line per record: each pair's per-judge support and the majority)

A pair is hallucinated when its support is "unsupported" or "contradicted". The majority label of a
binary field is the value given by more than half of the judges. Confidence intervals are 95%
bootstrap intervals that resample records, since pairs within a record are not independent.
"""
import collections
import itertools
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BOOTSTRAP = 2000
HALLUCINATED = ('unsupported', 'contradicted')


def load(name):
    return {v['pair_id']: v for line in (HERE / name / 'verdicts.jsonl').read_text().splitlines() if line.strip()
            for v in json.loads(line)['verdicts']}


def cohen(a, b):
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = collections.Counter(a), collections.Counter(b)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / n ** 2
    return (po - pe) / (1 - pe)


def fleiss(rows):
    """rows: one list of labels (one per judge) per item."""
    k = len(rows[0])
    cats = sorted({x for r in rows for x in r}, key=str)
    counts = [collections.Counter(r) for r in rows]
    p_i = [(sum(c[x] ** 2 for x in cats) - k) / (k * (k - 1)) for c in counts]
    p_j = [sum(c[x] for c in counts) / (len(rows) * k) for x in cats]
    pe = sum(p ** 2 for p in p_j)
    return (sum(p_i) / len(rows) - pe) / (1 - pe)


def ci(by_record, rng):
    keys = list(by_record)
    stats = []
    for _ in range(BOOTSTRAP):
        flags = [f for key in rng.choices(keys, k=len(keys)) for f in by_record[key]]
        stats.append(100 * sum(flags) / len(flags))
    stats.sort()
    return [round(stats[int(0.025 * BOOTSTRAP)], 1), round(stats[int(0.975 * BOOTSTRAP)], 1)]


def main():
    judges = [a.strip('/') for a in sys.argv[1:]]
    verdicts = {j: load(j) for j in judges}
    records = json.loads((HERE / 'sample_records.json').read_text())
    pair_ids = [p['pair_id'] for r in records for p in r['pairs']]
    missing = {j: sum(p not in verdicts[j] for p in pair_ids) for j in judges}
    assert not any(missing.values()), f'pairs missing: {missing}'
    source = {p['pair_id']: r['source'] for r in records for p in r['pairs']}
    record_of = {p['pair_id']: r['id'] for r in records for p in r['pairs']}
    half = len(judges) / 2

    halluc = {j: [verdicts[j][p]['support'] in HALLUCINATED for p in pair_ids] for j in judges}
    answerable = {j: [verdicts[j][p]['answerable_from_code'] for p in pair_ids] for j in judges}
    support = {j: [verdicts[j][p]['support'] for p in pair_ids] for j in judges}
    votes = [sum(halluc[j][i] for j in judges) for i in range(len(pair_ids))]
    majority = [v > half for v in votes]
    majority_answerable = [sum(answerable[j][i] for j in judges) > half for i in range(len(pair_ids))]

    rng = random.Random(0)

    def rate(flags, subset=None):
        idx = [i for i, p in enumerate(pair_ids) if subset is None or source[p] == subset]
        by_record = collections.defaultdict(list)
        for i in idx:
            by_record[record_of[pair_ids[i]]].append(flags[i])
        records_hit = sum(any(f) for f in by_record.values())
        return {'pairs_%': round(100 * sum(flags[i] for i in idx) / len(idx), 1), 'pairs_95ci': ci(by_record, rng),
                'records_with_one_or_more_%': round(100 * records_hit / len(by_record), 1)}

    summary = {
        'judges': judges, 'records': len(records), 'pairs': len(pair_ids),
        'hallucinated': {name: {s or 'all': rate(flags, s) for s in (None, 'cvefixes', 'msr')}
                         for name, flags in [*halluc.items(), ('majority', majority)]},
        'votes_for_hallucinated_%': {f'{n}_of_{len(judges)}': round(100 * votes.count(n) / len(votes), 1)
                                     for n in range(len(judges) + 1)},
        'answerable_from_code_%': {**{j: round(100 * sum(a) / len(a), 1) for j, a in answerable.items()},
                                   'majority': round(100 * sum(majority_answerable) / len(majority_answerable), 1)},
        'support_%': {j: {s: round(100 * support[j].count(s) / len(pair_ids), 1)
                          for s in ('supported', 'partly_supported', 'unsupported', 'contradicted')} for j in judges},
        'pairwise': {f'{a} vs {b}': {
            'hallucinated_agreement_%': round(100 * sum(x == y for x, y in zip(halluc[a], halluc[b])) / len(pair_ids), 1),
            'hallucinated_kappa': round(cohen(halluc[a], halluc[b]), 3),
            'support_kappa': round(cohen(support[a], support[b]), 3),
            'answerable_kappa': round(cohen(answerable[a], answerable[b]), 3)}
            for a, b in itertools.combinations(judges, 2)},
        'agreement_with_majority_%': {j: round(100 * sum(x == y for x, y in zip(halluc[j], majority)) / len(pair_ids), 1)
                                      for j in judges},
        'fleiss_kappa': {
            'hallucinated': round(fleiss([[halluc[j][i] for j in judges] for i in range(len(pair_ids))]), 3),
            'support': round(fleiss([[support[j][i] for j in judges] for i in range(len(pair_ids))]), 3),
            'answerable_from_code': round(fleiss([[answerable[j][i] for j in judges] for i in range(len(pair_ids))]), 3)},
    }
    # Error types of majority-hallucinated pairs, counted when most judges who flagged the pair agree on the type.
    types = collections.Counter()
    for i, p in enumerate(pair_ids):
        if majority[i]:
            given = collections.Counter(verdicts[j][p]['error_type'] for j in judges if halluc[j][i])
            top, n = given.most_common(1)[0]
            types[top if n > sum(given.values()) / 2 else 'no_agreement'] += 1
    summary['majority_error_types'] = dict(types.most_common())
    (HERE / 'summary.json').write_text(json.dumps(summary, indent=1) + '\n')

    with open(HERE / 'majority_verdicts.jsonl', 'w') as f:
        i = 0
        for r in records:
            rows = []
            for p in r['pairs']:
                rows.append({'pair_id': p['pair_id'], **{j: verdicts[j][p['pair_id']]['support'] for j in judges},
                             'votes_hallucinated': votes[i], 'majority_hallucinated': majority[i],
                             'majority_answerable_from_code': majority_answerable[i]})
                i += 1
            f.write(json.dumps({'record_id': r['id'], 'source': r['source'], 'pairs': rows}) + '\n')
    print(json.dumps({k: summary[k] for k in ('votes_for_hallucinated_%', 'fleiss_kappa', 'agreement_with_majority_%')}, indent=1))
    print('majority hallucinated:', summary['hallucinated']['majority']['all'])


if __name__ == '__main__':
    main()
