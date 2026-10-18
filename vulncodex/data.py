"""Load VulnCodeX records and splits.

The dataset is one file of records (data/vulncodex.jsonl.gz); every split is a list of record ids
(data/splits/). A question--answer pair is identified as "<record id>#<k>", k = 1, 2, ... in
conversation order; the benchmark, judge and ablation files use these pair ids.

    from vulncodex import load_split
    test = load_split('cve', 'test')                      # main split of the paper
    c_train = load_split('language/C', 'train')           # per-language subset of the cve split
"""
import gzip
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / 'data'
DATASET = DATA_DIR / 'vulncodex.jsonl.gz'
SPLIT_SCHEMES = ['cve', 'temporal', 'cross_language', 'random']
_cache = {}


def load_records(path=DATASET):
    """All records, in file order, as a list of dicts."""
    path = Path(path)
    if path not in _cache:
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(path, 'rt', encoding='utf-8') as f:
            _cache[path] = [json.loads(line) for line in f]
    return _cache[path]


def split_ids(scheme, split):
    """Record ids of one split, e.g. split_ids('cve', 'test') or split_ids('language/C', 'train')."""
    return json.loads((DATA_DIR / 'splits' / f'{scheme}.json').read_text())[split]


def load_split(scheme, split, path=DATASET):
    """Records of one split, in the order of the id list."""
    by_id = {r['id']: r for r in load_records(path)}
    return [by_id[i] for i in split_ids(scheme, split)]


def pairs(record):
    """(pair id, question, answer, topic) for every question--answer pair of a record."""
    conv = record['conversations']
    for k in range(len(conv) // 2):
        yield (f"{record['id']}#{k + 1}", conv[2 * k]['value'], conv[2 * k + 1]['value'],
               record['question_topics'][k])
