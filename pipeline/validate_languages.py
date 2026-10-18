"""Compare the predicted language of every record with the language recorded in the source data.

Usage:  python pipeline/validate_languages.py
Reads:  work/clean/clean_lang.json
        work/raw/cvefixes_descriptions.csv   (programming_language per CODE_ID)
        work/raw/bigvul.csv                (lang per CODE_ID: C or CPP)
        pipeline/language_validation/record_languages_v1.json   version 1 labels, which the adjudicated sample was drawn from
        pipeline/language_validation/disagreements_adjudicated.csv   (optional) hand verdicts, see below
Writes: pipeline/reports/language_validation.json       agreement rates, confusion tables and, if the
                                               adjudicated file exists, estimated accuracy
        pipeline/language_validation/disagreements_sample.csv   the random sample of disagreements to adjudicate

The source labels are not ground truth. The CVEFixes label is the language of the repository
(radare2's C code is labelled Lua, vim's C code Shell), and Big-Vul labels most Chromium and
Android C++ as C. So agreement is reported, and the disagreements are sampled for a person to
decide which side is right.

The sample is drawn from the disagreements of the first version of the labels (FRAME_LABELS), so
it stays the same when the labels are later corrected. The adjudicated file holds a true language
per record, in two kinds of rows: "sample" rows are that random sample; "changed" rows are every
record outside the sampled disagreements whose label has changed since, checked in full.

The estimate assumes a label is correct when it agrees with the source and has not changed. Per
source, the wrong records are the share of sample rows whose current label is wrong, scaled to
all first-version disagreements, plus the wrong "changed" rows. Snippets that are valid C and C++
alike and come from a C++ file ("undecidable") count as neither right nor wrong. Records whose
source label cannot be compared (CVEFixes "unknown", Objective-C, Shell, ...) are not covered.
"""
import json
import math
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'work' / 'clean' / 'clean_lang.json'
CVEFIXES = ROOT / 'work' / 'raw' / 'cvefixes_descriptions.csv'
MSR = ROOT / 'work' / 'raw' / 'bigvul.csv'
OUT = ROOT / 'pipeline' / 'reports' / 'language_validation.json'
SAMPLE_OUT = ROOT / 'pipeline' / 'language_validation' / 'disagreements_sample.csv'
ADJUDICATED = ROOT / 'pipeline' / 'language_validation' / 'disagreements_adjudicated.csv'
FRAME_LABELS = ROOT / 'pipeline' / 'language_validation' / 'record_languages_v1.json'
SAMPLE_SIZE = {'cvefixes': 100, 'msr': 50}
SEED = 0

# Source label -> the label set used in the dataset. Labels missing here ("unknown", Markdown,
# HTML, Shell, ...) cannot be compared and are counted separately.
SOURCE_TO_DATASET = {
    'C': 'C', 'C++': 'C++', 'CPP': 'C++', 'C#': 'C#', 'Go': 'Go', 'Java': 'Java',
    'JavaScript': 'JavaScript/TypeScript', 'TypeScript': 'JavaScript/TypeScript',
    'PHP': 'PHP', 'Python': 'Python', 'Ruby': 'Ruby', 'Rust': 'Rust', 'Scala': 'Scala',
    'Swift': 'Swift', 'Lua': 'Lua', 'Kotlin': 'Kotlin',
}
# C++ code without C++-only syntax is labelled C by design, so C/C++ confusions are also
# reported with the two merged.
FAMILY = {'C': 'C/C++', 'C++': 'C/C++'}


def load():
    records = json.load(open(DATA))
    df = pd.DataFrame([{'id': r['id'], 'cve_id': r['cve_id'], 'predicted': r['language'],
                        'code': r['code']} for r in records])
    df['source'] = df['id'].str.split('_').str[0]
    cvefixes = pd.read_csv(CVEFIXES).dropna(subset=['CODE_ID']).drop_duplicates('CODE_ID')
    cvefixes = cvefixes.rename(columns={'CODE_ID': 'id', 'programming_language': 'source_label'})
    msr = pd.read_csv(MSR).rename(columns={'CODE_ID': 'id', 'lang': 'source_label'})
    labels = pd.concat([cvefixes[['id', 'source_label']], msr[['id', 'source_label']]])
    df = df.merge(labels, on='id', how='left')
    df['source_label'] = df['source_label'].fillna('missing')
    df['source_mapped'] = df['source_label'].map(SOURCE_TO_DATASET)
    frame = json.loads(FRAME_LABELS.read_text()) if FRAME_LABELS.exists() else None
    df['frame'] = df['id'].map(lambda k: frame[k]['language']) if frame else df['predicted']
    return df


def agreement(df):
    comparable = df[df['source_mapped'].notna()]
    exact = comparable['predicted'] == comparable['source_mapped']
    family = (comparable['predicted'].replace(FAMILY) == comparable['source_mapped'].replace(FAMILY))
    return {
        'records': len(df),
        'comparable': len(comparable),
        'not_comparable': df.loc[df['source_mapped'].isna(), 'source_label'].value_counts().to_dict(),
        'exact_agreement': round(float(exact.mean()), 4),
        'agreement_c_cpp_merged': round(float(family.mean()), 4),
        'disagreements': int((~exact).sum()),
        'disagreements_c_cpp_merged': int((~family).sum()),
    }


def wilson(k, n, z=1.96):
    """95% Wilson score interval for k successes out of n."""
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return centre - half, centre + half


def estimate_accuracy(df, report):
    """Scale the adjudicated sample up to all comparable records, per source."""
    adjudicated = pd.read_csv(ADJUDICATED)
    current = df.set_index('id')['predicted']
    adjudicated['current'] = adjudicated['id'].map(current)
    adjudicated['source'] = adjudicated['id'].str.split('_').str[0]
    undecidable = (adjudicated['true_language'] == 'C or C++') & adjudicated['current'].isin(['C', 'C++'])
    adjudicated['state'] = 'right'
    adjudicated.loc[~undecidable & (adjudicated['current'] != adjudicated['true_language']), 'state'] = 'wrong'
    adjudicated.loc[undecidable, 'state'] = 'undecidable'

    comparable = df[df['source_mapped'].notna()]
    frame_disagree = comparable['frame'] != comparable['source_mapped']
    changed = comparable[~frame_disagree & (comparable['predicted'] != comparable['frame'])]
    unchecked = sorted(set(changed['id']) - set(adjudicated.loc[adjudicated['kind'] == 'changed', 'id']))
    if unchecked:
        print(f'WARNING: {len(unchecked)} changed labels are not in {ADJUDICATED.name}; counted as wrong:',
              unchecked[:10])

    result, totals = {}, {'comparable': 0, 'wrong': 0, 'wrong_low': 0, 'wrong_high': 0, 'undecidable': 0}
    for source, part in adjudicated.groupby('source'):
        sample = part[part['kind'] == 'sample']
        extra = part[part['kind'] == 'changed']
        n = len(sample)
        wrong = (sample['state'] == 'wrong').sum()
        low, high = wilson(wrong, n)
        frame_disagreements = int(frame_disagree[comparable['source'] == source].sum())
        extra_wrong = int((extra['state'] == 'wrong').sum()) + sum(i.startswith(source) for i in unchecked)
        extra_undecidable = int((extra['state'] == 'undecidable').sum())
        est = {'first_version_disagreements': frame_disagreements, 'sampled': n,
               'wrong_in_sample': int(wrong),
               'undecidable_in_sample': int((sample['state'] == 'undecidable').sum()),
               'changed_outside_sample_frame': len(extra), 'wrong_changed': extra_wrong,
               'estimated_wrong': round(frame_disagreements * wrong / n) + extra_wrong,
               'estimated_wrong_95ci': [round(frame_disagreements * low) + extra_wrong,
                                        round(frame_disagreements * high) + extra_wrong],
               'estimated_undecidable': round(frame_disagreements * (sample['state'] == 'undecidable').sum() / n)
                                        + extra_undecidable}
        decided = report[source]['comparable'] - est['estimated_undecidable']
        est['estimated_accuracy'] = round(1 - est['estimated_wrong'] / decided, 4)
        est['estimated_accuracy_95ci'] = [round(1 - est['estimated_wrong_95ci'][1] / decided, 4),
                                          round(1 - est['estimated_wrong_95ci'][0] / decided, 4)]
        est['causes_of_wrong_labels'] = sample.loc[sample['state'] == 'wrong', 'cause_if_prediction_wrong'] \
            .dropna().value_counts().to_dict()
        result[source] = est
        totals['comparable'] += report[source]['comparable']
        totals['wrong'] += est['estimated_wrong']
        totals['wrong_low'] += est['estimated_wrong_95ci'][0]
        totals['wrong_high'] += est['estimated_wrong_95ci'][1]
        totals['undecidable'] += est['estimated_undecidable']
    decided = totals['comparable'] - totals['undecidable']
    result['overall'] = {'estimated_wrong': totals['wrong'],
                         'estimated_accuracy': round(1 - totals['wrong'] / decided, 4),
                         'estimated_accuracy_95ci': [round(1 - totals['wrong_high'] / decided, 4),
                                                     round(1 - totals['wrong_low'] / decided, 4)]}
    return result


def main():
    df = load()
    report = {'overall': agreement(df)}
    for source, part in df.groupby('source'):
        report[source] = agreement(part)
        table = pd.crosstab(part['source_label'], part['predicted'])
        report[source]['confusion'] = {row: {col: int(n) for col, n in table.loc[row].items() if n}
                                       for row in table.index}
    if ADJUDICATED.exists():
        report['estimated_accuracy'] = estimate_accuracy(df, report)
    OUT.write_text(json.dumps(report, indent=1, default=float) + '\n')

    disagree = df[df['source_mapped'].notna() & (df['frame'] != df['source_mapped'])]
    sample = pd.concat([disagree[disagree['source'] == s].sample(min(n, (disagree['source'] == s).sum()),
                                                                 random_state=SEED)
                        for s, n in SAMPLE_SIZE.items()])
    sample = sample[['id', 'cve_id', 'source_label', 'frame', 'code']].rename(columns={'frame': 'predicted'})
    sample = sample.assign(true_language='', note='')
    sample.to_csv(SAMPLE_OUT, index=False)

    for key in ['overall', 'cvefixes', 'msr']:
        print(key, {k: v for k, v in report[key].items() if k not in ('confusion', 'not_comparable')})
    for key, value in report.get('estimated_accuracy', {}).items():
        print('estimate', key, {k: v for k, v in value.items() if k != 'causes_of_wrong_labels'})
    print(f'wrote {OUT.relative_to(ROOT)} and {SAMPLE_OUT.relative_to(ROOT)} ({len(sample)} rows)')


if __name__ == '__main__':
    main()
