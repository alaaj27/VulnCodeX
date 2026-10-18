"""Print a batch the way Claude read it in the first-pass judging (not needed by other judges).

Usage:  python hallucination_analysis/judge_view.py NNN [first_record]
Code longer than MAX_LINES is shown as its first HEAD and last TAIL lines. Under each answer,
identifiers that the answer names (backticked, snake_case, CamelCase or call-like words) but that
do not occur anywhere in the full code are listed as "not in code", so location claims can still
be checked against the whole snippet.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BATCH_SIZE, MAX_LINES, HEAD, TAIL = 20, 150, 110, 40
IDENT = re.compile(r'`([^`]{2,60})`|\b([A-Za-z_]\w*_\w+|[a-z]+[A-Z]\w*|[A-Z][a-z]+[A-Z]\w*|\w+(?=\(\)))\b')


def missing(answer, code):
    names = set()
    for m in IDENT.finditer(answer):
        name = (m.group(1) or m.group(2)).strip().rstrip('()')
        if name and not re.fullmatch(r'CVE-\d+-\d+', name):
            names.add(name)
    return sorted(n for n in names if n not in code)


def main():
    b = int(sys.argv[1])
    first = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    records = json.loads((HERE / 'sample_records.json').read_text())[b * BATCH_SIZE:(b + 1) * BATCH_SIZE]
    for r in records[first:]:
        lines = r['code'].splitlines()
        code = r['code'] if len(lines) <= MAX_LINES else '\n'.join(
            lines[:HEAD] + [f'... [{len(lines) - HEAD - TAIL} lines omitted] ...'] + lines[-TAIL:])
        print(f"### RECORD {r['id']}  ({r['cve_id']}, {r['language']}, {len(lines)} lines)")
        print('DESC:', r['description'].strip()[:1500])
        print('CODE:\n' + code)
        for p in r['pairs']:
            print(f"[{p['pair_id'].split('#')[1]}] Q: {p['question']}\n    A: {p['answer']}")
            gone = missing(p['answer'], r['code'])
            if gone:
                print('    not in code:', ', '.join(gone))
        print()


if __name__ == '__main__':
    main()
