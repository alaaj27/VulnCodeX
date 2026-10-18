"""Reference-based text metrics for every benchmarked model: ROUGE-L, BLEU-4 and CIDEr-D.

Usage:  python benchmark/score_metrics.py [--split cve]
Reads:  data/splits/<split>.json (test ids; vulncodex.load_split) (reference answers), <model>/answers_<split>[_<variant>].jsonl for every
        model folder and prompt variant (ablations are keyed "<model>:<variant>")
Writes: metrics_<split>.json

Each model answer is compared with the dataset's reference answer to the same question.
- ROUGE-L: F-measure of the longest common subsequence (rouge-score, with stemming), averaged over
  pairs; the 95% interval is a bootstrap over records.
- BLEU-4: corpus-level BLEU (sacrebleu, default 13a tokenisation).
- CIDEr-D: corpus-level (pycocoevalcap); word weights come from the whole test set, so it is not
  defined for a single answer. Text is lower-cased and split into words and punctuation.
Main runs are scored on every test pair. Ablation runs (answers_<split>_<variant>.jsonl) are
scored on the pairs they answered (the ablation subset), and the same model's main answers on exactly
those pairs are scored as their baseline, keyed "<model>:code". Missing answers count as empty strings. References are themselves model-generated (about 15% are
not supported by their sources), so these metrics measure similarity to the reference, not correctness.
"""
import argparse
import json
import sys
import random
import re
from pathlib import Path

import numpy as np
import sacrebleu
from pycocoevalcap.cider.cider import Cider
from rouge_score import rouge_scorer

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from vulncodex import load_split  # noqa: E402
BOOTSTRAP = 1000
WORD = re.compile(r"\w+|[^\w\s]")


def tokens(text):
    return ' '.join(WORD.findall(text.lower()))


def load(path):
    return {json.loads(l)['pair_id']: json.loads(l)['answer'] for l in path.read_text().splitlines()}


def score(answers, pair_ids, reference, scorer, rng):
    """Metrics over the given pairs; missing answers count as empty strings."""
    hyp = [answers.get(p, '') for p in pair_ids]
    ref = [reference[p] for p in pair_ids]
    record_of = [p.split('#')[0] for p in pair_ids]
    record_ids = sorted(set(record_of))
    pos = {r: [] for r in record_ids}
    for i, r in enumerate(record_of):
        pos[r].append(i)
    rouge = np.array([scorer.score(r, h)['rougeL'].fmeasure if h else 0.0 for r, h in zip(ref, hyp)])
    boot = sorted(np.mean(np.concatenate([rouge[pos[r]] for r in rng.choices(record_ids, k=len(record_ids))]))
                  for _ in range(BOOTSTRAP))
    bleu = sacrebleu.corpus_bleu(hyp, [ref]).score
    cider, _ = Cider().compute_score({i: [tokens(r)] for i, r in enumerate(ref)},
                                     {i: [tokens(h) or '.'] for i, h in enumerate(hyp)})
    return {'records': len(record_ids), 'pairs': len(pair_ids), 'empty_answers': sum(not h for h in hyp),
            'rougeL_f': round(100 * rouge.mean(), 2),
            'rougeL_95ci': [round(100 * boot[int(0.025 * BOOTSTRAP)], 2), round(100 * boot[int(0.975 * BOOTSTRAP)], 2)],
            'bleu4': round(bleu, 2), 'cider_d': round(float(cider), 3),
            'answer_words_median': float(np.median([len(h.split()) for h in hyp]))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--split', default='cve')
    args = ap.parse_args()
    records = load_split(args.split, 'test')
    reference = {f"{r['id']}#{k}": t['value'].strip()
                 for r in records for k, t in enumerate(r['conversations'][1::2], 1)}
    all_pairs = list(reference)
    scorer = rouge_scorer.RougeScorer(['rougeL'], use_stemmer=True)
    rng = random.Random(0)
    out = {}
    for path in sorted(HERE.glob(f'*/answers_{args.split}*.jsonl')):
        variant = path.stem[len(f'answers_{args.split}_'):]
        name = path.parent.name
        answers = load(path)
        if not variant:
            # Main run: every test pair.
            out[name] = score(answers, all_pairs, reference, scorer, rng)
            print(name, out[name], flush=True)
            continue
        # Ablation run: only the records it answered (the ablation subset), and the same model's
        # main (code-only) answers on exactly those pairs as its baseline, keyed "<model>:code".
        subset = [p for p in all_pairs if p in answers]
        out[f'{name}:{variant}'] = score(answers, subset, reference, scorer, rng)
        if f'{name}:code' not in out:
            out[f'{name}:code'] = score(load(path.parent / f'answers_{args.split}.jsonl'), subset, reference, scorer, rng)
            print(f'{name}:code', out[f'{name}:code'], flush=True)
        print(f'{name}:{variant}', out[f'{name}:{variant}'], flush=True)
    (HERE / f'metrics_{args.split}.json').write_text(json.dumps(out, indent=1) + '\n')


if __name__ == '__main__':
    main()
