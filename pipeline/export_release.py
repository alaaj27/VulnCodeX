"""Write the released dataset file: one JSON record per line, gzipped.

Usage:  python pipeline/export_release.py
Reads:  work/clean/vulncodex_v3.json   (add_descriptions.py; 26,003 records)
Writes: data/vulncodex.jsonl.gz

Fields: id, source (CVEfixes or Big-Vul, from the id prefix), cve_id, language, description, code,
conversations (alternating human / gpt turns; the first question starts with the <code_sequence>
placeholder), question_topics (one topic per question--answer pair, see vulncodex/topics.py).
"""
import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from vulncodex.topics import topic_of  # noqa: E402

DATA = ROOT / 'work' / 'clean' / 'vulncodex_v3.json'
OUT = ROOT / 'data' / 'vulncodex.jsonl.gz'
SOURCE = {'cvefixes': 'CVEfixes', 'msr': 'Big-Vul'}


def main():
    records = json.loads(DATA.read_text())
    # mtime=0: the same input always gives byte-identical output
    with open(OUT, 'wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as gz:
        for r in records:
            conv = r['conversations']
            assert len(conv) % 2 == 0 and all(t['from'] == ('human' if k % 2 == 0 else 'gpt') for k, t in enumerate(conv))
            out = {'id': r['id'], 'source': SOURCE[r['id'].split('_')[0]], 'cve_id': r['cve_id'],
                   'language': r['language'], 'description': r['description'], 'code': r['code'],
                   'conversations': conv, 'question_topics': [topic_of(t['value']) for t in conv[0::2]]}
            gz.write((json.dumps(out, ensure_ascii=False) + '\n').encode('utf-8'))
    print(f'{len(records)} records -> {OUT} ({OUT.stat().st_size / 1e6:.1f} MB)')


if __name__ == '__main__':
    main()
