# Helpers sourced by the run scripts: start and stop a vLLM server on port 8011.
# Environments (see requirements/): VLLM_ENV holds vllm; EVAL_ENV holds the text-metric packages.
export HF_HOME=${HF_HOME:-$HOME/.cache/huggingface}
VENV=${VLLM_ENV:-.venvs/vllm}/bin
EVAL=${EVAL_ENV:-.venvs/eval}/bin
mkdir -p logs
# vLLM reserves a large virtual address space; with a low soft limit, memory-mapping large weight
# files fails ("Cannot allocate memory"). Raise the soft limit to the hard limit.
ulimit -v $(ulimit -Hv)

start_server() {  # $1 = served model name to wait for; the rest = vllm serve arguments
  local name=$1; shift
  if curl -s -m 3 localhost:8011/v1/models > /dev/null; then echo "port 8011 is busy; stopping"; exit 1; fi
  (eval exec $VENV/vllm serve "$@" > "logs/vllm_${name//\//_}.log" 2>&1) &
  server=$!
  for i in $(seq 1 120); do
    curl -s localhost:8011/v1/models | grep -q "\"$name\"" && return 0
    kill -0 $server 2> /dev/null || break
    sleep 10
  done
  echo "server for $name did not start; see logs/vllm_${name//\//_}.log"; exit 1
}

stop_server() {
  kill $server; wait $server 2> /dev/null
  while curl -s -m 3 localhost:8011/v1/models > /dev/null; do sleep 5; done
}

judge_server() {  # the LLM judge: gpt-oss-120b, as in the paper
  start_server openai/gpt-oss-120b openai/gpt-oss-120b --port 8011 --max-model-len 32768 --gpu-memory-utilization 0.92
}

# The benchmark models: <folder name>|<Hugging Face id>|<revision>|<extra vLLM arguments>
# Gemma gets a 12,288-token window: its tokenizer counts 5 of the (identical) prompts as too long for 8,192.
MODELS=(
  "foundation-sec-8b-instruct|fdtn-ai/Foundation-Sec-8B-Instruct|main|"
  "qwen2.5-coder-7b-instruct|Qwen/Qwen2.5-Coder-7B-Instruct|main|"
  "opencoder-8b-instruct|infly/OpenCoder-8B-Instruct|01badbbf10c2dfd7e2a0b5f570065ef44548576c|--trust-remote-code"
  "gemma-4-31b-it|google/gemma-4-31b-it|main|--limit-mm-per-prompt '{\"image\":0,\"audio\":0,\"video\":0}' --max-model-len 12288"
)

serve_model() {  # serve one entry of MODELS
  IFS='|' read -r name model rev extra <<< "$1"
  $VENV/hf download "$model" --revision "$rev" --exclude "original/*" > /dev/null || { echo "download failed: $model"; exit 1; }
  start_server "$name" "$model" --revision "$rev" --port 8011 --max-model-len 8192 --gpu-memory-utilization 0.90 \
      --served-model-name "$name" $extra
}
