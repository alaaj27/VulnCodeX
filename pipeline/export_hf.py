"""Build the Hugging Face dataset folder (configs per split scheme) from the release file.

Usage:  python pipeline/export_hf.py
Reads:  data/vulncodex.jsonl.gz, data/splits/, data/README.md (the dataset card body)
Writes: work/hf/dataset/<config>/<split>.jsonl.gz and work/hf/dataset/README.md (card with YAML header)

Configs: cve (default), temporal, cross_language, random, each with train/validation/test, and "all"
(one split, "full", with every record). Records are the same as in the release file.
"""
import gzip
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from vulncodex import load_records, load_split, SPLIT_SCHEMES  # noqa: E402

OUT = ROOT / 'work' / 'hf' / 'dataset'
SPLITS = ['train', 'validation', 'test']
RAW_NOTE = '''
## Raw files

`raw/` holds the inputs of the build pipeline (not loaded by any config): `generated.json.gz`, the
generation output before filtering (110,817 records, 540,654 pairs), and the CVE descriptions of the two
sources (`cvefixes_descriptions.csv.gz`, `bigvul.csv.gz`). Unzipped into `work/raw/` of the repository,
they let `pipeline/` rebuild the dataset and splits byte for byte.
'''


def write(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as gz:
        for r in records:
            gz.write((json.dumps(r, ensure_ascii=False) + '\n').encode('utf-8'))


def main():
    for d in SPLIT_SCHEMES + ['all']:
        shutil.rmtree(OUT / d, ignore_errors=True)
    configs = []
    for scheme in SPLIT_SCHEMES:
        for split in SPLITS:
            write(OUT / scheme / f'{split}.jsonl.gz', load_split(scheme, split))
        files = '\n'.join(f'  - split: {s}\n    path: {scheme}/{s}.jsonl.gz' for s in SPLITS)
        configs.append(f'- config_name: {scheme}\n' + ('  default: true\n' if scheme == 'cve' else '') + f'  data_files:\n{files}')
    write(OUT / 'all' / 'full.jsonl.gz', load_records())
    configs.append('- config_name: all\n  data_files:\n  - split: full\n    path: all/full.jsonl.gz')
    header = ('---\nlicense: cc-by-4.0\nlanguage:\n- en\ntask_categories:\n- question-answering\n- text-generation\n'
              'tags:\n- security\n- vulnerability\n- code\n- cve\n- llm-generated\npretty_name: VulnCodeX\n'
              'size_categories:\n- 10K<n<100K\nconfigs:\n' + '\n'.join(configs) + '\n---\n\n')
    body = (ROOT / 'data' / 'README.md').read_text()
    body = body.replace('# VulnCodeX data', '# VulnCodeX', 1)
    body = body.replace('`vulncodex.jsonl.gz` holds the whole dataset: 26,003 records, one JSON object per line. Every split in\n`splits/` is a list of record ids into this file.',
                        'Open-ended questions and answers about real vulnerable code. Code, scripts, model outputs and judge\nlabels: see the GitHub repository (link added after review).\n\n```python\nfrom datasets import load_dataset\ntest = load_dataset("<org>/VulnCodeX", "cve", split="test")\n```\n\nConfigs: `cve` (default; no CVE or code snippet crosses splits), `temporal` (test = CVEs from 2023 on),\n`cross_language` (test = languages unseen in training), `random` (for comparison only; leaks CVEs),\n`all` (every record).')
    i, j = body.index('## Loading'), body.index('## Question topics')
    body = body[:i] + body[j:]
    for old, new in [('(estimated 98.8% correct; see `pipeline/README.md`)', '(estimated 98.8% correct)'),
                     ('from the keyword rules in `vulncodex/topics.py`', 'from keyword rules (`vulncodex/topics.py` in the repository)'),
                     ('filtered\nwith explicit rules (`pipeline/`)', 'filtered\nwith explicit rules'),
                     (' (`hallucination_analysis/`)', ''),
                     ('(see `../DATA_LICENSE`)', ''), ('(see `../NOTICE`)', '(see NOTICE in the repository)')]:
        body = body.replace(old, new)
    body = body.replace('\n## Licence', RAW_NOTE + '\n## Licence')
    (OUT / 'README.md').write_text(header + body)
    # raw/ (generation output and source descriptions) is added by hand: gzip -9 -n work/raw/* into raw/
    print('wrote', OUT)


if __name__ == '__main__':
    main()
