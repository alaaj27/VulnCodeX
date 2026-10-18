#!/bin/bash
# The code-only benchmark (paper Section V-B): every model answers the test split, then text metrics and
# the LLM judge. Rerunning resumes: finished records are skipped by run_model.py and score_judge.py.
# Usage (one GPU with 80 GB): bash benchmark/run_benchmark.sh
# Before: python benchmark/build_prompts.py   (prompts_cve.jsonl is included, so this is optional)
set -u
cd "$(dirname "$0")/.."
source benchmark/serve.sh
names=""
for entry in "${MODELS[@]}"; do
  name=${entry%%|*}; names="$names $name"
  echo "== $name: answers $(date +%H:%M)"
  serve_model "$entry"
  $VENV/python benchmark/run_model.py --name "$name" --model "$name" || { stop_server; exit 1; }
  stop_server
done
echo "== text metrics $(date +%H:%M)"
$EVAL/python benchmark/score_metrics.py
echo "== judge $(date +%H:%M)"
judge_server
$VENV/python benchmark/score_judge.py --models $names
stop_server
$EVAL/python benchmark/breakdown.py
$EVAL/python benchmark/memorisation.py
echo "== done $(date +%H:%M)"
