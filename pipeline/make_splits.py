"""Split dataset version 3 in several ways, for different evaluation questions.

Usage:  python pipeline/make_splits.py
Reads:  work/clean/vulncodex_v3.json (written by add_descriptions.py)
Writes: data/splits/<scheme>.json            {"train": [ids], "validation": [ids], "test": [ids]}, in
                                             dataset order, for every scheme below
        data/splits/language/<Language>.json  the same, per language
        data/splits/split_report.json         size and composition of every split, chosen seeds, leakage
The records themselves are in data/vulncodex.jsonl.gz; vulncodex.load_split() joins the two.
data/splits/README.md (written by hand) explains the schemes to users.

Grouping: records that share a CVE identifier or an identical code snippet are joined into one group
(union-find, so the relation is transitive). Every scheme except "random" keeps each group in a single
split, so no CVE and no snippet occurs in two splits: 1,248 snippets carry more than one CVE, so a
split by CVE alone would leak code.

Schemes:
- random: records shuffled within each stratum (source x language) and cut 80/10/10. CVEs and
  snippets cross splits; the report gives how many test records share a CVE or snippet with train.
- cve: groups are taken in random order and each goes to the split whose shortfall is largest,
  against 80/10/10 targets for the records of every stratum (source x language x CVE year before /
  from 2023) and for the number of CVEs. TRIES orders are tried; the most balanced is kept.
- temporal: every group with a CVE from 2023 or later is test; other groups are split 8:1 into train
  and validation as in "cve". Tests on CVEs newer than most training data.
- language/<Language>: the records of one language, keeping their "cve" split, so these folders do
  not leak into each other or into "cve". Only languages with MIN_LANGUAGE_FOLDER records or more.
- cross_language: groups whose records are all in SEEN_LANGUAGES are split 8:1 into train and
  validation as in "cve"; groups whose records are all in other languages are test. Groups that mix
  seen and unseen languages are left out, since keeping them would leak a CVE into test.
"""
import collections
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'work' / 'clean' / 'vulncodex_v3.json'
OUT = ROOT / 'data' / 'splits'
SCHEMES = ['random', 'cve', 'temporal', 'cross_language']
# Languages that cross_language trains on: the four largest. Its test set holds every other language.
SEEN_LANGUAGES = {'C', 'C++', 'PHP', 'JavaScript/TypeScript'}
# language/<Language> folders exist only for languages with at least this many records; smaller
# ones would get validation and test sets of a few dozen records or fewer.
MIN_LANGUAGE_FOLDER = 500
# Folder names for language/<Language>; languages pooled as "Other" get no folder.
FOLDER = {'C++': 'Cpp', 'C#': 'CSharp', 'JavaScript/TypeScript': 'JavaScript_TypeScript'}
SPLITS = ['train', 'validation', 'test']
RATIOS = {'train': 0.8, 'validation': 0.1, 'test': 0.1}
TEMPORAL_FROM = 2023
SEED = 0
# Number of random group orders tried; the most balanced assignment is kept.
TRIES = 300
# Targets (strata, CVE count) with fewer records than this are not scored, being too small to balance.
MIN_SCORED = 200


def groups_of(records):
    parent = list(range(len(records)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    first = {}
    for i, r in enumerate(records):
        for key in ('cve:' + r['cve_id'], 'code:' + r['code']):
            if key in first:
                parent[find(i)] = find(first[key])
            else:
                first[key] = i
    groups = collections.defaultdict(list)
    for i in range(len(records)):
        groups[find(i)].append(i)
    return list(groups.values())


def stratum(r):
    return r['id'].split('_')[0] + '|' + r['language'] + '|' + ('recent' if year(r) >= TEMPORAL_FROM else 'older')


def targets(g, records):
    """What a group contributes to each balancing target: records per stratum, and its CVEs."""
    out = collections.Counter(stratum(records[i]) for i in g)
    out['#cves'] = len({records[i]['cve_id'] for i in g})
    return out


def assign(groups, records, ratios, rng):
    """Greedy stratified assignment of whole groups; returns {record index: split}."""
    contribution = [targets(g, records) for g in groups]
    totals = sum(contribution, collections.Counter())
    counts = {s: collections.Counter() for s in ratios}
    order = list(range(len(groups)))
    rng.shuffle(order)
    out = {}
    for n in order:
        g, g_strata = groups[n], contribution[n]

        def shortfall(s):
            return sum(n * (ratios[s] * totals[k] - counts[s][k]) / totals[k] for k, n in g_strata.items())

        best = max(ratios, key=shortfall)
        counts[best].update(g_strata)
        for i in g:
            out[i] = best
    return out


def imbalance(split_of, groups, records, ratios):
    """Largest relative deviation from the target share, over all targets that are large enough."""
    totals, counts = collections.Counter(), {s: collections.Counter() for s in ratios}
    for g in groups:
        t = targets(g, records)
        totals.update(t)
        counts[split_of[g[0]]].update(t)
    for s in ratios:
        counts[s]['#records'] = sum(v for k, v in counts[s].items() if k != '#cves')
    totals['#records'] = sum(v for k, v in totals.items() if k != '#cves')
    return max(abs(counts[s][k] / totals[k] - ratios[s]) / ratios[s]
               for s in ratios for k in totals if totals[k] >= MIN_SCORED)


def best_assignment(groups, records, ratios):
    """Try TRIES seeded orders; keep the assignment with the smallest imbalance."""
    best = None
    for seed in range(SEED, SEED + TRIES):
        split_of = assign(groups, records, ratios, random.Random(seed))
        score = imbalance(split_of, groups, records, ratios)
        if best is None or score < best[0]:
            best = (score, seed, split_of)
    return best


def describe(records, idx):
    rs = [records[i] for i in idx]
    return {'records': len(rs), 'pairs': sum(len(r['conversations']) // 2 for r in rs),
            'cves': len({r['cve_id'] for r in rs}), 'snippets': len({r['code'] for r in rs}),
            'msr_%': round(100 * sum(r['id'].startswith('msr') for r in rs) / max(len(rs), 1), 1),
            'languages_%': {k: round(100 * v / len(rs), 1)
                            for k, v in collections.Counter(r['language'] for r in rs).most_common()},
            'cve_year_2023_or_later_%': round(100 * sum(year(r) >= TEMPORAL_FROM for r in rs) / max(len(rs), 1), 1)}


def year(r):
    return int(r['cve_id'].split('-')[1])


def check(records, split_of):
    """No CVE and no snippet may occur in two splits (split_of is a list parallel to records)."""
    for key in ('cve_id', 'code'):
        seen = collections.defaultdict(set)
        for r, s in zip(records, split_of):
            seen[r[key]].add(s)
        assert all(len(v) == 1 for v in seen.values()), f'{key} crosses splits'


def random_split(records, rng):
    """Stratified record-level split; ignores groups."""
    by_stratum = collections.defaultdict(list)
    for i, r in enumerate(records):
        by_stratum[r['id'].split('_')[0] + '|' + r['language']].append(i)
    out = {}
    for idx in by_stratum.values():
        rng.shuffle(idx)
        n_train, n_val = round(RATIOS['train'] * len(idx)), round(RATIOS['validation'] * len(idx))
        for k, i in enumerate(idx):
            out[i] = 'train' if k < n_train else 'validation' if k < n_train + n_val else 'test'
    return out


def leakage(records, split_of):
    """Share of test records whose CVE or snippet also occurs in train."""
    train_cves = {r['cve_id'] for i, r in enumerate(records) if split_of.get(i) == 'train'}
    train_code = {r['code'] for i, r in enumerate(records) if split_of.get(i) == 'train'}
    test = [r for i, r in enumerate(records) if split_of.get(i) == 'test']
    return {'test_records_with_cve_in_train_%': round(100 * sum(r['cve_id'] in train_cves for r in test) / len(test), 1),
            'test_records_with_snippet_in_train_%': round(100 * sum(r['code'] in train_code for r in test) / len(test), 1)}


def write(path, records, split_of):
    """One file per scheme: the record ids of each split, in dataset order."""
    path.parent.mkdir(parents=True, exist_ok=True)
    ids = {s: [r['id'] for i, r in enumerate(records) if split_of.get(i) == s] for s in SPLITS}
    path.write_text('{\n' + ',\n'.join(f' "{s}": {json.dumps(v)}' for s, v in ids.items()) + '\n}\n')


def main():
    records = json.loads(DATA.read_text())
    groups = groups_of(records)
    meta = {'input': DATA.name, 'groups': len(groups), 'largest_group_records': max(map(len, groups)),
            'orders_tried': TRIES}
    splits, scores = {}, {}

    splits['random'] = random_split(records, random.Random(SEED))

    scores['cve'], meta['cve_seed'], splits['cve'] = best_assignment(groups, records, RATIOS)

    recent = [g for g in groups if any(year(records[i]) >= TEMPORAL_FROM for i in g)]
    older = [g for g in groups if g not in recent]
    scores['temporal'], meta['temporal_seed'], splits['temporal'] = best_assignment(
        older, records, {'train': 8 / 9, 'validation': 1 / 9})
    splits['temporal'].update({i: 'test' for g in recent for i in g})
    meta['temporal_test_from_year'] = TEMPORAL_FROM

    seen = [g for g in groups if all(records[i]['language'] in SEEN_LANGUAGES for i in g)]
    unseen = [g for g in groups if not any(records[i]['language'] in SEEN_LANGUAGES for i in g)]
    mixed = [g for g in groups if g not in seen and g not in unseen]
    scores['cross_language'], meta['cross_language_seed'], splits['cross_language'] = best_assignment(
        seen, records, {'train': 8 / 9, 'validation': 1 / 9})
    splits['cross_language'].update({i: 'test' for g in unseen for i in g})
    meta['cross_language_seen'] = sorted(SEEN_LANGUAGES)
    meta['cross_language_left_out'] = {'groups': len(mixed), 'records': sum(map(len, mixed))}
    meta['max_relative_deviation'] = {k: round(v, 3) for k, v in scores.items()}

    for name in ('cve', 'temporal', 'cross_language'):
        check([r for i, r in enumerate(records) if i in splits[name]],
              [splits[name][i] for i in range(len(records)) if i in splits[name]])

    report = dict(meta)
    for name in SCHEMES:
        write(OUT / f'{name}.json', records, splits[name])
        report[name] = {s: describe(records, [i for i in range(len(records)) if splits[name].get(i) == s])
                        for s in SPLITS}
    report['random']['leakage'] = leakage(records, splits['random'])

    languages = collections.Counter(r['language'] for r in records)
    report['language'] = {}
    for lang, n in languages.most_common():
        if lang == 'Other' or n < MIN_LANGUAGE_FOLDER:
            continue
        sub = {i: s for i, s in splits['cve'].items() if records[i]['language'] == lang}
        write(OUT / 'language' / f'{FOLDER.get(lang, lang)}.json', records, sub)
        report['language'][lang] = {s: sum(v == s for v in sub.values()) for s in SPLITS}

    (OUT / 'split_report.json').write_text(json.dumps(report, indent=1) + '\n')
    for name in SCHEMES:
        for s in SPLITS:
            d = report[name][s]
            print(f"{name:14s} {s:10s} records {d['records']:6,d}  pairs {d['pairs']:7,d}  CVEs {d['cves']:5,d}  "
                  f"MSR {d['msr_%']:4.1f}%  2023+ {d['cve_year_2023_or_later_%']:4.1f}%  "
                  f"top languages {list(d['languages_%'].items())[:3]}")
    print('random leakage', report['random']['leakage'])
    print('cross_language left out', meta['cross_language_left_out'])
    print('per language', report['language'])


if __name__ == '__main__':
    main()
