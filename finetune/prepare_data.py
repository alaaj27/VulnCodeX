"""Build the supervised fine-tuning files from the CVE-grouped splits (severity questions left out).

Usage:  python finetune/prepare_data.py [--split cve]
Reads:  data/splits/<split>.json (train and validation ids; vulncodex.load_split)
Writes: work/finetune/data/<split>_no_severity/{train,validation}.jsonl
        work/finetune/data/<split>_no_severity/report.json

One example per record, in exactly the format of the code-only benchmark (benchmark/
build_prompts.py): the user message holds the code and all of the record's questions, and the target is
the reference answers as a numbered list. Code is shortened as in the benchmark (OpenCoder tokenizer,
5,200 tokens, first and last lines kept), so training inputs look like test inputs.

Severity questions are removed before numbering (the authors' decision: 53% of severity answers were
judged hallucinated, since CVE descriptions rarely state a severity). A record left with no question would
be dropped; the test split is not touched, so evaluation uses the benchmark's prompts unchanged.
"""
import argparse
import collections
import json
import sys
from pathlib import Path

from transformers import AutoTokenizer

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'benchmark'))
from build_prompts import INTRO, PLACEHOLDER, TEMPLATE, TOKENIZER, TOKENIZER_REVISION, shorten  # noqa: E402
from vulncodex import load_split  # noqa: E402
from vulncodex.topics import topic_of  # noqa: E402

OUT = ROOT / 'work' / 'finetune' / 'data'
DROP_TOPICS = {'Severity'}


def example(record, tok):
    pairs = [(q['value'].replace(PLACEHOLDER, '').strip(), a['value'].strip())
             for q, a in zip(record['conversations'][0::2], record['conversations'][1::2])]
    kept = [(q, a) for q, a in pairs if topic_of(q) not in DROP_TOPICS]
    if not kept:
        return None, len(pairs), 0, False
    code, short = shorten(record['code'], tok)
    prompt = TEMPLATE.format(
        intro=INTRO['code'].format(code=code, description=''),
        questions='\n'.join(f'{k}. {q}' for k, (q, _) in enumerate(kept, 1)),
        format='\n'.join(f'{k}. <answer>' for k in range(1, len(kept) + 1)))
    target = '\n'.join(f'{k}. {a}' for k, (_, a) in enumerate(kept, 1))
    return ({'id': record['id'], 'messages': [{'role': 'user', 'content': prompt},
                                               {'role': 'assistant', 'content': target}]},
            len(pairs), len(kept), short)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--split', default='cve')
    args = ap.parse_args()
    tok = AutoTokenizer.from_pretrained(TOKENIZER, trust_remote_code=True, revision=TOKENIZER_REVISION)
    out_dir = OUT / f'{args.split}_no_severity'
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {'split': args.split, 'dropped_topics': sorted(DROP_TOPICS)}
    for part in ('train', 'validation'):
        records = load_split(args.split, f'{part}')
        stats = collections.Counter()
        with open(out_dir / f'{part}.jsonl', 'w') as f:
            for r in records:
                ex, n_in, n_kept, short = example(r, tok)
                stats['pairs_in'] += n_in
                stats['pairs_kept'] += n_kept
                stats['shortened_code'] += short
                if ex is None:
                    stats['records_dropped'] += 1
                    continue
                stats['records'] += 1
                f.write(json.dumps(ex) + '\n')
        report[part] = dict(stats, pairs_dropped=stats['pairs_in'] - stats['pairs_kept'])
        print(part, report[part])
    (out_dir / 'report.json').write_text(json.dumps(report, indent=1) + '\n')


if __name__ == '__main__':
    main()
