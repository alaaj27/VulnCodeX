"""Convert the judge's shorthand verdict files into one record-wise verdicts file.

Usage:  python hallucination_analysis/claude-opus-5-5/convert_raw.py
Reads:  ../sample_records.json, raw/batch_NNN.txt
Writes: verdicts.jsonl   (one line per record, records in sample order)

Shorthand, used only to save writing when the judge is Claude in a chat session:
    @<record id>                      starts a record
    <k> <rel> <sup> <ans> <err> <reason>
k is the pair number; rel and ans are 1/0 (question_relevant, answerable_from_code); sup is
s/p/u/c (supported, partly_supported, unsupported, contradicted); err is one of the codes below
or "-" for none; the reason is the rest of the line. For supported pairs the "-" may be left out.
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ANNOTATOR = HERE.name
SUPPORT = {'s': 'supported', 'p': 'partly_supported', 'u': 'unsupported', 'c': 'contradicted'}
ERROR = {'-': None, 'loc': 'wrong_location', 'ident': 'invented_identifier', 'type': 'wrong_vulnerability_type',
         'mech': 'wrong_mechanism', 'impact': 'wrong_impact', 'ver': 'wrong_version_or_product',
         'sev': 'unfounded_severity', 'fix': 'inapplicable_fix', 'gen': 'generic_or_evasive', 'other': 'other'}


def parse(path):
    """Return {record id: [pair verdict, ...]} for one shorthand file."""
    out, record = {}, None
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith('@'):
            record = line[1:].strip()
            out[record] = []
            continue
        k, rel, sup, ans, rest = line.split(maxsplit=4)
        err, _, reason = rest.partition(' ')
        if sup == 's' and err not in ERROR:
            err, reason = '-', rest
        out[record].append({'pair_id': f'{record}#{k}', 'question_relevant': rel == '1', 'support': SUPPORT[sup],
                            'answerable_from_code': ans == '1', 'error_type': ERROR[err], 'reason': reason})
    return out


def main():
    verdicts = {}
    for path in sorted((HERE / 'raw').glob('batch_*.txt')):
        verdicts.update(parse(path))
    records = json.loads((HERE.parent / 'sample_records.json').read_text())
    with open(HERE / 'verdicts.jsonl', 'w') as f:
        for r in records:
            if r['id'] in verdicts:
                f.write(json.dumps({'record_id': r['id'], 'cve_id': r['cve_id'], 'source': r['source'],
                                    'language': r['language'], 'annotator': ANNOTATOR,
                                    'verdicts': verdicts[r['id']]}) + '\n')
    print(f'{len(verdicts)} records, {sum(map(len, verdicts.values()))} verdicts -> {HERE / "verdicts.jsonl"}')


if __name__ == '__main__':
    main()
