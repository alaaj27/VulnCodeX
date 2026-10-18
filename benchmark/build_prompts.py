"""Build one benchmark prompt per test record (the same prompts for every model).

Usage:  python benchmark/build_prompts.py [--split cve] [--variant code]
Reads:  data/splits/<split>.json (test ids; vulncodex.load_split)
Writes: benchmark/prompts_<split>.jsonl for the main variant "code",
        prompts_<split>_<variant>.jsonl for the ablations (record_id, pair_ids, truncated, prompt)

Variants (what the model sees besides the questions):
  code       the code only (main setting; no CVE identifier, no description)
  no_code    nothing: how much can be answered from general knowledge and the question alone
  code_desc  the code and the CVE description: how much the description adds
  desc_only  the CVE description only: how far the description alone goes
The model gets all of the record's questions at once and answers them in a numbered list. The
questions are the dataset's questions with the <code_sequence> placeholder removed. The prompt is a
single user message, since some chat templates (Gemma) have no system role.

Length: OpenCoder-8B-Instruct accepts 8,192 tokens in total. Code longer than CODE_TOKEN_LIMIT tokens
(OpenCoder tokenizer) keeps its first and last lines, with a marker for the lines left out, so that every
model receives exactly the same input.
"""
import argparse
import json
import sys
from pathlib import Path

from transformers import AutoTokenizer

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from vulncodex import load_split  # noqa: E402
TOKENIZER = 'infly/OpenCoder-8B-Instruct'
TOKENIZER_REVISION = '01badbbf10c2dfd7e2a0b5f570065ef44548576c'  # inspected: custom code is a SentencePiece tokenizer
CODE_TOKEN_LIMIT = 5200
PLACEHOLDER = '<code_sequence>'

INTRO = {
    'code': '''You are a software security expert. The following code snippet contains a known security vulnerability.

```
{code}
```

Answer each of the following questions about the vulnerability in this code.''',
    'no_code': '''You are a software security expert. A code snippet contains a known security vulnerability. The code is not shown to you.

Answer each of the following questions about the vulnerability as well as you can.''',
    'code_desc': '''You are a software security expert. The following code snippet contains a known security vulnerability, described in the CVE description below.

CVE description: {description}

```
{code}
```

Answer each of the following questions about the vulnerability in this code.''',
    'desc_only': '''You are a software security expert. A code snippet contains a known security vulnerability, described in the CVE description below. The code is not shown to you.

CVE description: {description}

Answer each of the following questions about the vulnerability as well as you can.''',
}

TEMPLATE = '''{intro} Keep each answer short (one to three sentences).

{questions}

Reply with a numbered list that has exactly one answer per question, in the same order:
{format}'''


def shorten(code, tok):
    """Keep head and tail lines so that the code fits CODE_TOKEN_LIMIT tokens."""
    if len(tok(code)['input_ids']) <= CODE_TOKEN_LIMIT:
        return code, False
    lines = code.split('\n')
    keep = len(lines)
    while keep > 2:
        keep -= max(1, keep // 20)
        head, tail = lines[:keep // 2], lines[-(keep - keep // 2):]
        out = '\n'.join(head + [f'... [{len(lines) - keep} lines omitted] ...'] + tail)
        if len(tok(out)['input_ids']) <= CODE_TOKEN_LIMIT:
            return out, True
    raise ValueError('cannot shorten')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--split', default='cve')
    ap.add_argument('--variant', default='code', choices=list(INTRO))
    args = ap.parse_args()
    suffix = '' if args.variant == 'code' else f'_{args.variant}'
    tok = AutoTokenizer.from_pretrained(TOKENIZER, trust_remote_code=True, revision=TOKENIZER_REVISION)
    records = load_split(args.split, 'test')
    n_short = 0
    with open(HERE / f'prompts_{args.split}{suffix}.jsonl', 'w') as f:
        for r in records:
            questions = [t['value'].replace(PLACEHOLDER, '').strip() for t in r['conversations'][0::2]]
            code, short = shorten(r['code'], tok)
            uses_code = '{code}' in INTRO[args.variant]
            n_short += short and uses_code
            prompt = TEMPLATE.format(
                intro=INTRO[args.variant].format(code=code, description=r['description']),
                questions='\n'.join(f'{k}. {q}' for k, q in enumerate(questions, 1)),
                format='\n'.join(f'{k}. <answer>' for k in range(1, len(questions) + 1)))
            f.write(json.dumps({'record_id': r['id'], 'pair_ids': [f"{r['id']}#{k}" for k in range(1, len(questions) + 1)],
                                'truncated': short and uses_code, 'prompt': prompt}) + '\n')
    print(f'{len(records)} prompts, {n_short} with shortened code -> prompts_{args.split}{suffix}.jsonl')


if __name__ == '__main__':
    main()
