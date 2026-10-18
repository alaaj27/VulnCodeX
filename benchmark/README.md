# Benchmark and ablation

Every model's answers and LLM-judge labels for the code-only benchmark (paper Section V-B, Table V,
Fig. 4) and the input ablation (Section V-C, Fig. 5, Table IX), with the scripts that produced and
scored them.

## Task

Each model answers all 11,733 questions of the 2,576 records in the `cve` test split. It sees one
prompt per record with the code and all of the record's questions, but not the CVE id or description
(`prompts_cve.jsonl`; Appendix E of the paper shows the prompt). Models run under vLLM at temperature 0
with at most 1,500 output tokens.

## Scoring

- **LLM-as-judge** (`score_judge.py`, prompt in `judge_prompt.md`): gpt-oss-120b sees the CVE
  description and the code as evidence, and each question with its reference and the model's answer.
  It labels the answer correct, partially correct or incorrect, grading against the evidence when the
  reference is wrong. Score: correct 1, partially correct 0.5, incorrect 0.
- **Reference-based metrics** (`score_metrics.py`): ROUGE-L, corpus BLEU-4, CIDEr-D. They track
  wording more than correctness, so we report them for comparison only.

All intervals are 95% bootstrap intervals over records.

## Results

| Model (folder) | LLM-as-judge | 95% CI |
|---|---|---|
| `foundation-sec-8b-instruct` | 32.0 | 30.8–33.2 |
| `qwen2.5-coder-7b-instruct` | 32.7 | 31.5–34.0 |
| `opencoder-8b-instruct` | 29.3 | 28.0–30.5 |
| `gemma-4-31b-it` | 40.2 | 38.8–41.6 |
| `qwen2.5-coder-7b-vulncodex` (fine-tuned, see `finetune/`) | 35.4 | 34.3–36.7 |

Summaries: `judge_cve.json` (judge scores), `metrics_cve.json` (text metrics),
`breakdown_cve.json` (by topic, language and source), `memorisation_cve.json` (old vs recent CVEs).

## Ablation

`gemma-4-31b-it` answers 1,000 test records (`ablation_records.json`, drawn by
`make_ablation_subset.py`) with three more inputs: no code, code and CVE description, description only.
`ablation_model.txt` gives the rule that chose the model.

| Input | LLM-as-judge (999 records) |
|---|---|
| No code | 16.8 |
| Code only (the benchmark task) | 39.8 |
| Description only | 83.9 |
| Code and description | 86.3 |

`ablation_results.json` has the intervals and paired differences, and `ablation_options/data.json` the
scores per question topic (Table IX). On the six *description topics* (type, mechanism, fix, impact,
exploitation, affected software) the model scores 34.4 from the code and 93.8 from the description.

## Files

Per model folder:

| File | What it is |
|---|---|
| `answers_cve[_<variant>].jsonl` | One line per pair: `{"pair_id", "answer"}` (empty if the reply had no answer for it) |
| `judged_cve[_<variant>].jsonl` | One line per pair: `{"pair_id", "correctness", "reference_wrong", "reason"}` |
| `run_cve[_<variant>].json` | Run settings, timing and parsing counts |

The variant suffix is absent for the code-only benchmark and `_no_code`, `_code_desc` or `_desc_only`
for the ablation. Pair ids (`<record id>#<k>`) join with the dataset (`vulncodex.pairs`).

Scripts, in the order they run:

| Script | What it does |
|---|---|
| `build_prompts.py [--variant v]` | Builds `prompts_cve[_<variant>].jsonl` from the test split |
| `make_ablation_subset.py` | Draws the ablation records and cuts the ablation prompt files to them |
| `serve.sh` | Server helpers and the model list, sourced by the run scripts |
| `run_benchmark.sh` | Serves each model, answers, then text metrics, judge, breakdowns (GPU) |
| `run_ablation.sh` | The three ablation inputs for Gemma-4-31B, then scoring (GPU) |
| `run_model.py` | Sends the prompts to a served model and parses the numbered answers |
| `score_metrics.py`, `score_judge.py` | Text metrics; LLM judge |
| `breakdown.py`, `memorisation.py` | Scores by topic, language and source; by CVE year |
| `ablation_results.py`, `ablation_options.py` | Ablation scores overall and by topic |

Raw model and judge responses are not included; the answers and labels are parsed from them unchanged.
Without a GPU, every summary can be recomputed from the included files, for example
`python benchmark/score_metrics.py` or `python benchmark/ablation_results.py`.
