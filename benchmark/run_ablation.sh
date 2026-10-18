#!/bin/bash
# The input ablation (paper Section V-C): Gemma-4-31B answers the 1,000 ablation records
# (ablation_records.json) without the code, with code and CVE description, and with the description only.
# Then text metrics, the LLM judge, and the scores (ablation_results.json, ablation_options/data.json).
# ablation_model.txt records why this model was chosen. Run after run_benchmark.sh (it reuses the
# code-only answers). Usage: bash benchmark/run_ablation.sh
# Before: build_prompts.py --variant <v> for each variant, then make_ablation_subset.py (the cut prompt
# files are included, so this is optional).
set -u
cd "$(dirname "$0")/.."
source benchmark/serve.sh
entry=$(printf '%s\n' "${MODELS[@]}" | grep '^gemma-4-31b-it|')
name=${entry%%|*}
serve_model "$entry"
keys=""
for variant in no_code code_desc desc_only; do
  echo "== $name: $variant $(date +%H:%M)"
  $VENV/python benchmark/run_model.py --name "$name" --model "$name" --variant "$variant" || { stop_server; exit 1; }
  keys="$keys $name:$variant"
done
stop_server
echo "== text metrics $(date +%H:%M)"
$EVAL/python benchmark/score_metrics.py
echo "== judge $(date +%H:%M)"
judge_server
$VENV/python benchmark/score_judge.py --models $keys
stop_server
$EVAL/python benchmark/ablation_results.py --model "$name"
$EVAL/python benchmark/ablation_options.py
echo "== done $(date +%H:%M)"
