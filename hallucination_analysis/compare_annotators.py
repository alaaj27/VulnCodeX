"""Agreement between two annotators' verdicts.

Usage:  python hallucination_analysis/compare_annotators.py <annotator dir A> <annotator dir B>
Reads:  <A>/verdicts.jsonl, <B>/verdicts.jsonl (pairs judged by both are compared)
Writes: agreement_<A>__<B>.json
"""
import collections
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    return {v['pair_id']: v for line in (HERE / name / 'verdicts.jsonl').read_text().splitlines() if line.strip()
            for v in json.loads(line)['verdicts']}


def kappa(a, b):
    n = len(a)
    observed = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = collections.Counter(a), collections.Counter(b)
    expected = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / n ** 2
    return round((observed - expected) / (1 - expected), 3) if expected < 1 else None


def compare(label, a, b):
    return {'agreement_%': round(100 * sum(x == y for x, y in zip(a, b)) / len(a), 1), 'cohen_kappa': kappa(a, b),
            'confusion (A -> B)': {f'{x} -> {y}': c for (x, y), c in sorted(collections.Counter(zip(a, b)).items())}}


def main():
    name_a, name_b = sys.argv[1].strip('/'), sys.argv[2].strip('/')
    va, vb = load(name_a), load(name_b)
    ids = [k for k in va if k in vb]
    get = lambda v, f: [f(v[k]) for k in ids]
    halluc = lambda v: v['support'] in ('unsupported', 'contradicted')
    out = {'A': name_a, 'B': name_b, 'pairs_compared': len(ids),
           'hallucinated_%': {name_a: round(100 * sum(get(va, halluc)) / len(ids), 1),
                              name_b: round(100 * sum(get(vb, halluc)) / len(ids), 1)},
           'support (4 labels)': compare('support', get(va, lambda v: v['support']), get(vb, lambda v: v['support'])),
           'hallucinated (yes/no)': compare('h', get(va, halluc), get(vb, halluc)),
           'answerable_from_code': compare('a', get(va, lambda v: v['answerable_from_code']),
                                           get(vb, lambda v: v['answerable_from_code'])),
           'question_relevant': compare('q', get(va, lambda v: v['question_relevant']),
                                        get(vb, lambda v: v['question_relevant']))}
    both = [k for k in ids if halluc(va[k]) and halluc(vb[k])]
    out['error_type_agreement_on_pairs_both_call_hallucinated'] = compare(
        'e', [va[k]['error_type'] for k in both], [vb[k]['error_type'] for k in both]) if both else None
    path = HERE / f'agreement_{name_a}__{name_b}.json'
    path.write_text(json.dumps(out, indent=1) + '\n')
    print(json.dumps({k: v for k, v in out.items() if 'error_type' not in k}, indent=1))


if __name__ == '__main__':
    main()
