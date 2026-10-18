"""Check one annotator's verdicts against the sample and summarise the labels.

Usage:  python hallucination_analysis/check_verdicts.py <annotator dir> [batch number ...]
Reads:  sample_records.json, <annotator dir>/verdicts.jsonl
Writes: <annotator dir>/results.json (only when every record is judged and valid)

verdicts.jsonl has one line per record: {"record_id", "cve_id", "source", "language", "annotator",
"verdicts": [one object per pair, in the format of prompt.md]}. Checks that every pair ID appears
exactly once with valid labels. With batch numbers it only checks those batches and writes nothing.
"""
import collections
import json
import math
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUPPORT = ['supported', 'partly_supported', 'unsupported', 'contradicted']
ERRORS = {'wrong_location', 'invented_identifier', 'wrong_vulnerability_type', 'wrong_mechanism',
          'wrong_impact', 'wrong_version_or_product', 'unfounded_severity', 'inapplicable_fix',
          'generic_or_evasive', 'other'}
BATCH_SIZE = 20
BOOTSTRAP = 2000


def load_verdicts(path):
    """Return {record id: [pair verdict, ...]} and a list of problems."""
    by_record, problems = {}, []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f'line {n}: not JSON')
            continue
        if r.get('record_id') in by_record:
            problems.append(f"{r.get('record_id')}: record appears twice")
        by_record[r.get('record_id')] = r.get('verdicts', [])
    return by_record, problems


def check_batch(b, records, by_record):
    expected = [p['pair_id'] for r in records[b * BATCH_SIZE:(b + 1) * BATCH_SIZE] for p in r['pairs']]
    rows = [v for r in records[b * BATCH_SIZE:(b + 1) * BATCH_SIZE] for v in by_record.get(r['id'], [])]
    if not rows:
        return [], [f'batch {b}: missing']
    problems = []
    for v in rows:
        if v.get('support') not in SUPPORT:
            problems.append(f"{v.get('pair_id')}: support {v.get('support')!r}")
        if not isinstance(v.get('question_relevant'), bool) or not isinstance(v.get('answerable_from_code'), bool):
            problems.append(f"{v.get('pair_id')}: boolean field")
        if v.get('support') == 'supported' and v.get('error_type') is not None:
            problems.append(f"{v.get('pair_id')}: error_type on a supported pair")
        if v.get('support') != 'supported' and v.get('error_type') not in ERRORS:
            problems.append(f"{v.get('pair_id')}: error_type {v.get('error_type')!r}")
    got = [v.get('pair_id') for v in rows]
    if got != expected:
        missing, extra = set(expected) - set(got), set(got) - set(expected)
        dup = [k for k, c in collections.Counter(got).items() if c > 1]
        problems.append(f'batch {b}: missing {sorted(missing)[:5]} extra {sorted(extra)[:5]} '
                        f'duplicates {dup[:5]} order_ok {sorted(got) == sorted(expected)}')
    return rows, problems


def share(rows, test):
    return 100 * sum(map(test, rows)) / len(rows)


def cluster_ci(by_record, test, rng):
    """95% bootstrap interval of a pair-level share, resampling records (pairs within a record are not independent)."""
    keys = list(by_record)
    stats = []
    for _ in range(BOOTSTRAP):
        rows = [v for k in rng.choices(keys, k=len(keys)) for v in by_record[k]]
        stats.append(share(rows, test))
    stats.sort()
    return [round(stats[int(0.025 * BOOTSTRAP)], 1), round(stats[int(0.975 * BOOTSTRAP)], 1)]


def main():
    annotator = (HERE / sys.argv[1]).resolve()
    records = json.loads((HERE / 'sample_records.json').read_text())
    by_record, all_problems = load_verdicts(annotator / 'verdicts.jsonl')
    unknown = set(by_record) - {r['id'] for r in records}
    all_problems += [f'{k}: record not in the sample' for k in sorted(unknown)]
    n_batches = math.ceil(len(records) / BATCH_SIZE)
    wanted = [int(a) for a in sys.argv[2:]] or range(n_batches)
    all_rows = []
    for b in wanted:
        rows, problems = check_batch(b, records, by_record)
        all_problems += problems
        all_rows += rows or []
    for p in all_problems:
        print('PROBLEM', p)
    print(f'{len(all_rows)} verdicts checked, {len(all_problems)} problems')
    if sys.argv[2:] or all_problems:
        return

    meta = {p['pair_id']: (r['id'], r['source']) for r in records for p in r['pairs']}
    all_rows = [dict(v, record_id=meta[v['pair_id']][0], source=meta[v['pair_id']][1]) for v in all_rows]

    rng = random.Random(0)
    def summary(rows):
        by_record = collections.defaultdict(list)
        for v in rows:
            by_record[v['record_id']].append(v)
        bad = lambda v: v['support'] in ('unsupported', 'contradicted')
        out = {'records': len(by_record), 'pairs': len(rows),
               'support_%': {s: round(share(rows, lambda v, s=s: v['support'] == s), 1) for s in SUPPORT},
               'hallucinated_%': round(share(rows, bad), 1),
               'hallucinated_95ci': cluster_ci(by_record, bad, rng),
               'not_fully_supported_%': round(share(rows, lambda v: v['support'] != 'supported'), 1),
               'question_relevant_%': round(share(rows, lambda v: v['question_relevant']), 1),
               'answerable_from_code_%': round(share(rows, lambda v: v['answerable_from_code']), 1),
               'records_with_a_hallucinated_pair_%': round(100 * sum(any(map(bad, g)) for g in by_record.values())
                                                           / len(by_record), 1),
               'error_types': dict(collections.Counter(v['error_type'] for v in rows if v['error_type']).most_common())}
        return out
    results = {'all': summary(all_rows)}
    for source in ['cvefixes', 'msr']:
        results[source] = summary([v for v in all_rows if v['source'] == source])
    (annotator / 'results.json').write_text(json.dumps(results, indent=1) + '\n')
    print(json.dumps(results['all'], indent=1))


if __name__ == '__main__':
    main()
