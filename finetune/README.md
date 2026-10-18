# Fine-tuning

Does training on VulnCodeX help a model answer from the code alone, on vulnerabilities it has never seen
(paper Section V-D, Fig. 6, Appendix F)?

## Setup

- **Model**: Qwen2.5-Coder-7B-Instruct with a LoRA adapter (rank 16, α 32, dropout 0.05, all linear
  layers; 0.5% of the parameters). All settings are in `train_lora.py` and `run_config.json`.
- **Data**: the `cve` training split, in exactly the benchmark's code-only format: the prompt with the
  code and all of a record's questions, and the reference answers as the target (loss on the answer
  tokens only). Severity questions are left out, following the hallucination analysis
  (`prepare_data.py`): 93,654 pairs from 20,832 records.
- **Training**: learning rate 1e-4, cosine schedule, effective batch 32 records, bf16, validation loss
  every 100 steps on 600 validation records. The validation loss was lowest after 600 steps (0.92
  epochs, about two hours on one A100) and rose at step 700, so training was stopped and the
  checkpoint after 600 steps kept (`training_log.json`).
- **Evaluation**: the adapter is served with vLLM on top of the unchanged base model and answers the test
  split exactly like the benchmark models; its answers and judge labels are in
  `benchmark/qwen2.5-coder-7b-vulncodex/`.

## Results (`comparison_cve.json`)

Paired comparison with the base model on the same questions (one test record that the judge could not
grade for the fine-tuned model is left out of both); 95% intervals are paired bootstraps over records.

| | Base | Fine-tuned | Difference (95% CI) |
|---|---|---|---|
| All questions | 32.7 | 35.4 | +2.8 (1.6 to 3.9) |
| Exploitation (largest gain) | 27.7 | 36.4 | +8.7 (5.7 to 11.7) |

Five of the six description topics (exploitation, impact, type, mechanism, fix) improve significantly;
`comparison_cve.json` has every topic, CVE period and source.

## Files

| File | What it does |
|---|---|
| `prepare_data.py` | Builds the training and validation files (`work/finetune/data/`) |
| `train_lora.py` | Trains the adapter (TRL SFTTrainer + PEFT); resumes from the latest checkpoint |
| `run_finetune.sh` | Data, training, answers, scoring and comparison in one run (GPU) |
| `compare.py` | Paired comparison with the base model → `comparison_cve.json` |
| `run_config.json`, `training_log.json` | Settings and loss history of the run reported in the paper |

To reproduce the paper's adapter, train with `run_finetune.sh` and keep the checkpoint after 600 steps
(the run continues to two epochs unless stopped). The adapter is released on Hugging Face as
`Llama-VulnCodeX-Qwen2.5-Coder-7B-LoRA` (link added on publication); the Llama 3.1 licence of the
training answers requires the name to begin with "Llama".
