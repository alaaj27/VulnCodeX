"""Add the CVE description to every record and repair truncated CVE identifiers (dataset version 3).

Usage:  python pipeline/add_descriptions.py
Reads:  work/clean/clean_lang.json
        work/raw/cvefixes_descriptions.csv (CODE_ID, cve_id, description)
        work/raw/bigvul.csv (CODE_ID, CVE ID, Summary)
Writes: work/clean/vulncodex_v3.json
        pipeline/reports/descriptions_report.json

The description is the text the generating model was given. CVEFixes stores it as a list of
{"lang", "value"} entries; we keep the English value. Where the record's CVE identifier is a
truncated form of the identifier in the source (it is a prefix of it), the source identifier is used.
Field order of a version-3 record: id, cve_id, language, description, code, conversations.
"""
import ast
import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
IN = ROOT / 'work' / 'clean' / 'clean_lang.json'
CVEFIXES = ROOT / 'work' / 'raw' / 'cvefixes_descriptions.csv'
MSR = ROOT / 'work' / 'raw' / 'bigvul.csv'
OUT = ROOT / 'work' / 'clean' / 'vulncodex_v3.json'
REPORT = ROOT / 'pipeline' / 'reports' / 'descriptions_report.json'


def english(text):
    text = text.strip()
    if text.startswith('['):
        entries = ast.literal_eval(text)
        return next(e['value'] for e in entries if e.get('lang') == 'en').strip()
    return text


def main():
    records = json.loads(IN.read_text())
    cvefixes = pd.read_csv(CVEFIXES).dropna(subset=['CODE_ID']).set_index('CODE_ID')
    msr = pd.read_csv(MSR).set_index('CODE_ID')
    out, repaired = [], {}
    for r in records:
        source, cve_col, desc_col = ((cvefixes, 'cve_id', 'description') if r['id'].startswith('cvefixes')
                                     else (msr, 'CVE ID', 'Summary'))
        row = source.loc[r['id']]
        source_cve = str(row[cve_col]).strip()
        cve = r['cve_id']
        if cve != source_cve:
            assert source_cve.startswith(cve), (r['id'], cve, source_cve)
            repaired[r['id']] = [cve, source_cve]
            cve = source_cve
        description = english(row[desc_col])
        assert description, r['id']
        out.append({'id': r['id'], 'cve_id': cve, 'language': r['language'], 'description': description,
                    'code': r['code'], 'conversations': r['conversations']})
    OUT.write_text(json.dumps(out))
    report = {'input': IN.name, 'output': OUT.name, 'records': len(out),
              'cves': len({r['cve_id'] for r in out}),
              'description_words_median': sorted(len(r['description'].split()) for r in out)[len(out) // 2],
              'cve_ids_repaired': repaired}
    REPORT.write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps(report, indent=1))


if __name__ == '__main__':
    main()
