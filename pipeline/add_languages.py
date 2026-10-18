"""Write a copy of the cleaned dataset with a "language" field on every record.

Usage:  python pipeline/add_languages.py
Reads:  work/clean/clean.json   (left untouched)
        pipeline/reports/record_languages.json   (written by detect_languages.py)
Writes: work/clean/clean_lang.json

A first version of the labels, before the C++ rule was fixed, is kept in
pipeline/language_validation/record_languages_v1.json: validate_languages.py drew its hand-checked
sample from it.

The languages are predicted from the code, so they are approximate; "Other" marks snippets
with no confident prediction.
"""
import collections
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'work' / 'clean' / 'clean.json'
LANGUAGES = ROOT / 'pipeline' / 'reports' / 'record_languages.json'
OUT = ROOT / 'work' / 'clean' / 'clean_lang.json'


def main():
    with open(DATA) as f:
        records = json.load(f)
    language_of = {k: v['language'] for k, v in json.loads(LANGUAGES.read_text()).items()}
    labelled = [{'id': r['id'], 'cve_id': r['cve_id'], 'language': language_of[r['id']],
                 'code': r['code'], 'conversations': r['conversations']} for r in records]
    with open(OUT, 'w') as f:
        json.dump(labelled, f, indent=4)
    counts = collections.Counter(r['language'] for r in labelled)
    for language, count in counts.most_common():
        print(f'{language:24s} {count:6,d}')
    print('wrote', OUT, f'({len(labelled):,} records)')


if __name__ == '__main__':
    main()
