# VulnCodeX

**Open-ended questions and answers about real vulnerable code.** VulnCodeX pairs 26,003 vulnerable
functions from 6,911 CVEs in ten programming languages with conversations about their vulnerability:
what it is, where it is, how it works, how it is exploited, what it affects and how to fix it.
119,118 question–answer pairs in total, built from CVEfixes and Big-Vul.

Vulnerability datasets usually give one label per function (vulnerable or not, or a CWE category).
VulnCodeX gives the explanation a developer needs to act on it, for training and evaluating models that
explain vulnerabilities rather than only detect them.

This repository contains the dataset, its leakage-free splits, every script used to build and evaluate
it, and all model outputs and judge scores reported in the paper.

## Quick start

```python
from vulncodex import load_split, pairs      # standard library only

test = load_split("cve", "test")             # 2,576 records whose CVEs and code are absent from training
record = test[0]
print(record["cve_id"], record["language"])
print(record["code"])
for pair_id, question, answer, topic in pairs(record):
    print(f"[{topic}] {question}\n  -> {answer}")
```

The dataset is also on Hugging Face (link added on publication).

## What is in the data

| | |
|---|---|
| Records | 26,003 vulnerable functions, each with its CVE id, CVE description, language and a conversation |
| Question–answer pairs | 119,118 (median 5 per record) |
| CVEs | 6,911, from 1999 to 2024 |
| Languages | C, PHP, C++, JavaScript/TypeScript, Java, Python, Ruby, Go, C#, Rust |
| Splits | `cve` (main; no CVE or snippet crosses splits), `temporal` (CVEs from 2023 on), `cross_language`, per language, `random` (for comparison only) |

See [`data/README.md`](data/README.md) for the record format and question topics, and
[`data/splits/README.md`](data/splits/README.md) for the splits.

## Main results

Code-only benchmark on the `cve` test split (11,733 questions), scored by an LLM judge (gpt-oss-120b;
correct = 1, partially correct = 0.5). Reference-based metrics are reported for comparison; they rank
the models almost in reverse, so we recommend the LLM-as-judge score.

| Model | LLM-as-judge | ROUGE-L | BLEU-4 | CIDEr |
|---|---|---|---|---|
| Foundation-Sec-8B-Instruct | 32.0 | 32.0 | 11.4 | 0.37 |
| Qwen2.5-Coder-7B-Instruct | 32.7 | 29.8 | 10.6 | 0.40 |
| OpenCoder-8B-Instruct | 29.3 | 31.9 | 10.8 | 0.43 |
| Gemma-4-31B-it | **40.2** | 25.0 | 7.6 | 0.34 |
| Qwen2.5-Coder-7B-Instruct, fine-tuned on VulnCodeX (LoRA) | 35.4 | 42.3 | 20.1 | 1.19 |

- **Hallucination analysis.** Three LLM judges from different model families find 85.2% of the answers
  in a 1,000-record sample supported or partly supported by the code or the CVE description. The
  remaining errors concentrate in a few predictable topics (severity, location, fix).
- **Ablation.** Given the CVE description, Gemma-4-31B answers 84–86% of the questions; from the code
  alone, 40%. Most questions ask for knowledge about the vulnerability that the function does not state,
  which is what VulnCodeX pairs with the code.
- **Fine-tuning.** Less than one epoch of LoRA training raises Qwen2.5-Coder-7B by 2.8 points
  (95% CI 1.6–3.9) on CVEs it has not seen, with the largest gains on exploitation, impact and
  vulnerability type.

## Repository layout

```
data/                      the dataset (vulncodex.jsonl.gz) and the splits (record ids)
vulncodex/                 loader and question-topic rules (standard library only)
pipeline/                  building the dataset: cleaning, languages, descriptions, splits, release file
hallucination_analysis/    the 1,000-record sample, three judges' labels, majority vote, agreement
benchmark/                 prompts, every model's answers and judge labels, text metrics, ablation
finetune/                  training data preparation, LoRA training, comparison with the base model
figures/                   scripts that rebuild the paper's figures and tables (output in figures/out/)
requirements/              pinned Python environments
```

Each folder has a README with its files and commands.

## Reproducing the paper

All result files are included, so every number can be recomputed without a GPU. Rerunning the models
needs one 80 GB GPU (A100).

| Paper | Command | Output |
|---|---|---|
| Dataset (Section III) | `python pipeline/export_release.py` after the pipeline steps in `pipeline/README.md` | `data/vulncodex.jsonl.gz` |
| Splits (Section III-E) | `python pipeline/make_splits.py` | `data/splits/` |
| Table III, Fig. 2, Fig. 3 | `python figures/make_dataset_stats.py`; `python figures/question_diversity.py` | `figures/out/` |
| Table IV (hallucination analysis) | `python hallucination_analysis/summarize_judges.py claude-opus-5-5 deepseek-v4-flash-0731 gpt-oss-120b` | `hallucination_analysis/summary.json` |
| Table V (benchmark) | `bash benchmark/run_benchmark.sh` (GPU), or from the included answers: `python benchmark/score_metrics.py` | `benchmark/metrics_cve.json`, `judge_cve.json` |
| Fig. 4 (old and recent CVEs) | `python benchmark/memorisation.py`; `python figures/memorisation_figure.py` | `benchmark/memorisation_cve.json` |
| Fig. 5, Table IX (ablation) | `bash benchmark/run_ablation.sh` (GPU), or `python benchmark/ablation_results.py`; `python benchmark/ablation_options.py` | `benchmark/ablation_results.json` |
| Fig. 6 (fine-tuning) | `bash finetune/run_finetune.sh` (GPU), or `python finetune/compare.py` | `finetune/comparison_cve.json` |
| Figure PDFs | `python figures/*_figure.py`; `python figures/export_figures.py` (needs Tectonic) | `figures/out/fig_*.pdf` |

The scripts were run from the repository root. Their outputs were checked against the files in this
repository: the pipeline rebuilds the released dataset and splits byte for byte from the generation
output.

## Environments

The `vulncodex` package needs only Python 3.11+. The experiments used three environments, pinned in
`requirements/`: `vllm.txt` (serving models, building prompts), `eval.txt` (metrics, statistics,
figures, pipeline) and `train.txt` (fine-tuning). The run scripts find them through `VLLM_ENV`,
`EVAL_ENV` and `TRAIN_ENV` (default `.venvs/<name>`).

## Licences

- Data: [CC BY 4.0](DATA_LICENSE), with attribution to CVEfixes (CC BY 4.0) and Big-Vul (MIT).
- Code: [MIT](LICENSE).
- The question–answer pairs were generated with Llama 3.1; see [NOTICE](NOTICE). Under the Llama 3.1
  Community License, a model trained on this data and made available must have a name beginning
  with "Llama".

## Citation

Citation information will be added after the review period.
