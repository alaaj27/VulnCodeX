#!/bin/bash
# Fine-tuning (paper Section V-D): prepare the training data, train a LoRA adapter on
# Qwen2.5-Coder-7B-Instruct, answer the test split with it exactly like the benchmark models, score it
# (text metrics, LLM judge), and compare it with the base model (comparison_cve.json).
# Rerunning resumes: training continues from its latest checkpoint, and finished records are skipped.
# Usage (one A100 80GB; training takes about two hours): bash finetune/run_finetune.sh
set -u -o pipefail
cd "$(dirname "$0")/.."
source benchmark/serve.sh
TRAIN=${TRAIN_ENV:-.venvs/train}/bin
RUN=qwen2.5-coder-7b_cve_no_severity
NAME=qwen2.5-coder-7b-vulncodex          # benchmark folder for the fine-tuned model
ADAPTER=work/finetune/runs/$RUN/adapter

echo "== data $(date +%H:%M)"
[ -f work/finetune/data/cve_no_severity/train.jsonl ] || $VENV/python finetune/prepare_data.py || exit 1
echo "== training $(date +%H:%M)"
[ -f $ADAPTER/adapter_config.json ] || $TRAIN/python finetune/train_lora.py --run $RUN || exit 1

echo "== answers $(date +%H:%M)"
start_server $NAME Qwen/Qwen2.5-Coder-7B-Instruct --port 8011 --max-model-len 8192 --gpu-memory-utilization 0.90 \
  --enable-lora --max-lora-rank 16 --lora-modules $NAME=$ADAPTER
$VENV/python benchmark/run_model.py --name $NAME --model $NAME || { stop_server; exit 1; }
stop_server
echo "== text metrics $(date +%H:%M)"
$EVAL/python benchmark/score_metrics.py
echo "== judge $(date +%H:%M)"
judge_server
$VENV/python benchmark/score_judge.py --models $NAME
stop_server
$EVAL/python finetune/compare.py
echo "== done $(date +%H:%M)"
