"""Draw the 1,000-record sample for the LLM-judge hallucination check and attach CVE descriptions.

Usage:  python hallucination_analysis/make_sample.py      (from the project folder)
Reads:  work/clean/clean_lang.json (pipeline step 3)
        work/raw/cvefixes_descriptions.csv (description per CODE_ID)
        work/raw/bigvul.csv (Summary per CODE_ID)
Writes: hallucination_analysis/sample_records.json
        hallucination_analysis/batches/batch_NNN.txt   (records as the judge sees them)

The sample is stratified by source in proportion to the dataset (seeded). Each pair gets an ID
"<record id>#<k>", k counting from 1. The batch files hold exactly what the judge is shown after
the prompt in prompt.md; they can be given to another model unchanged.
"""
import json
import random
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
DATA = ROOT / 'work' / 'clean' / 'clean_lang.json'
CVEFIXES = ROOT / 'work' / 'raw' / 'cvefixes_descriptions.csv'
MSR = ROOT / 'work' / 'raw' / 'bigvul.csv'
OUT = HERE / 'sample_records.json'
BATCHES = HERE / 'batches'
SAMPLE_SIZE = 1000
BATCH_SIZE = 20
SEED = 0
PLACEHOLDER = '<code_sequence>\n'


def descriptions():
    cvefixes = pd.read_csv(CVEFIXES).dropna(subset=['CODE_ID']).drop_duplicates('CODE_ID')
    msr = pd.read_csv(MSR)
    out = dict(zip(cvefixes['CODE_ID'], cvefixes['description']))
    out.update(zip(msr['CODE_ID'], msr['Summary']))
    return out


def render(record):
    lines = [f"### RECORD {record['id']}", f"CVE: {record['cve_id']}   Language: {record['language']}",
             'CVE DESCRIPTION:', record['description'].strip(), 'CODE:', '```', record['code'], '```',
             'QA PAIRS:']
    for pair in record['pairs']:
        lines += [f"[{pair['pair_id']}]", f"Q: {pair['question']}", f"A: {pair['answer']}"]
    return '\n'.join(lines)


def main():
    records = json.load(open(DATA))
    description = descriptions()
    rng = random.Random(SEED)
    sample = []
    for prefix in ['cvefixes', 'msr']:
        group = [r for r in records if r['id'].startswith(prefix)]
        sample += rng.sample(group, round(SAMPLE_SIZE * len(group) / len(records)))
    rng.shuffle(sample)
    out = []
    for r in sample:
        turns = r['conversations']
        pairs = [{'pair_id': f"{r['id']}#{k + 1}",
                  'question': turns[2 * k]['value'].replace(PLACEHOLDER, '', 1).strip(),
                  'answer': turns[2 * k + 1]['value'].strip()} for k in range(len(turns) // 2)]
        desc = description.get(r['id'])
        assert isinstance(desc, str) and desc.strip(), r['id']
        out.append({'id': r['id'], 'cve_id': r['cve_id'], 'source': r['id'].split('_')[0],
                    'language': r['language'], 'description': desc, 'code': r['code'], 'pairs': pairs})
    OUT.write_text(json.dumps(out, indent=1))
    BATCHES.mkdir(exist_ok=True)
    for b in range(0, len(out), BATCH_SIZE):
        text = '\n\n'.join(render(r) for r in out[b:b + BATCH_SIZE])
        (BATCHES / f'batch_{b // BATCH_SIZE:03d}.txt').write_text(text + '\n')
    print(f"{len(out)} records, {sum(len(r['pairs']) for r in out)} pairs, "
          f"{sum(r['source'] == 'msr' for r in out)} MSR; {len(out) // BATCH_SIZE} batches -> {HERE}")


if __name__ == '__main__':
    main()
