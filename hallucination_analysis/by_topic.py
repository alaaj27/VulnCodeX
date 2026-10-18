"""Majority-vote hallucination and answerable-from-code rates by question topic.

Usage:  python hallucination_analysis/by_topic.py   (after summarize_judges.py)
Reads:  sample_records.json, majority_verdicts.jsonl; topic rules from vulncodex/topics.py
Writes: by_topic.json
"""
import collections
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from vulncodex.topics import topic_of  # noqa: E402

question = {p['pair_id']: p['question'] for r in json.loads((HERE / 'sample_records.json').read_text()) for p in r['pairs']}
groups = collections.defaultdict(list)
for line in (HERE / 'majority_verdicts.jsonl').read_text().splitlines():
    for p in json.loads(line)['pairs']:
        groups[topic_of(question[p['pair_id']])].append(p)
out = {topic: {'pairs': len(ps),
               'hallucinated_%': round(100 * sum(p['majority_hallucinated'] for p in ps) / len(ps), 1),
               'answerable_from_code_%': round(100 * sum(p['majority_answerable_from_code'] for p in ps) / len(ps), 1)}
       for topic, ps in sorted(groups.items(), key=lambda kv: -sum(p['majority_hallucinated'] for p in kv[1]) / len(kv[1]))}
(HERE / 'by_topic.json').write_text(json.dumps(out, indent=1) + '\n')
print(json.dumps(out, indent=1))
