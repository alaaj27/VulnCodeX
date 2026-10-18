"""Draw the ablation subset and cut the ablation prompt files down to it.

Usage:  python benchmark/make_ablation_subset.py   (after build_prompts.py for every variant)
Reads:  data/splits/cve.json (test ids; vulncodex.load_split), prompts_cve_<variant>.jsonl for the ablation variants
Writes: ablation_records.json (the sampled record ids), and rewrites prompts_cve_<variant>.jsonl
        for no_code, code_desc and desc_only so that they hold only the sampled records.

SIZE records are drawn at random (seed 0) from the test split, in proportion to source (CVEFixes, MSR).
The main prompts (prompts_cve.jsonl) are not changed: every model answers the full test split.
"""
import json
import sys
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from vulncodex import load_split  # noqa: E402
SIZE = 1000
SEED = 0
VARIANTS = ['no_code', 'code_desc', 'desc_only']

records = load_split('cve', 'test')
rng = random.Random(SEED)
chosen = []
for prefix in ('cvefixes', 'msr'):
    group = sorted(r['id'] for r in records if r['id'].startswith(prefix))
    chosen += rng.sample(group, round(SIZE * len(group) / len(records)))
chosen = sorted(chosen)
(HERE / 'ablation_records.json').write_text(json.dumps({'seed': SEED, 'records': chosen}, indent=0) + '\n')
keep = set(chosen)
for v in VARIANTS:
    path = HERE / f'prompts_cve_{v}.jsonl'
    lines = [l for l in path.read_text().splitlines() if json.loads(l)['record_id'] in keep]
    path.write_text('\n'.join(lines) + '\n')
    print(v, len(lines), 'prompts')
print(len(chosen), 'records,', sum(c.startswith('msr') for c in chosen), 'from MSR')
