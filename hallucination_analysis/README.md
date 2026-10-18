# Hallucination analysis

How often are the generated answers not supported by the material they were generated from (paper
Section V-A, Table IV, Appendix D)? Three LLM judges from different model families, none from the Llama
family that generated the data, label every question–answer pair of a 1,000-record sample against the
record's CVE description and code.

## Results (from `summary.json`)

| % of pairs | Claude | DeepSeek | gpt-oss | Majority |
|---|---|---|---|---|
| Supported or partly supported | 83.4 | 85.7 | 83.5 | 85.2 |
| Hallucinated (unsupported or contradicted) | 16.6 | 14.3 | 16.5 | **14.8 (13.5–16.2)** |
| Answerable from the code alone | 33.1 | 43.0 | 28.3 | 34.6 |

The three judges give similar rates, and so do the two sources. Agreement on individual pairs is
moderate: Fleiss' κ = 0.58 for hallucinated (pairwise Cohen's κ 0.55–0.61), 0.51 for the four support
levels and 0.57 for answerable from code; disagreements are mostly borderline cases. The errors
concentrate in a few topics (`by_topic.json`): severity (53.4% hallucinated), location (32.7%) and fix
(26.5%), against 2.1–6.1% for impact, vulnerability type and mechanism.

## Judges

| Folder | Judge | How it ran |
|---|---|---|
| `claude-opus-5-5/` | Claude Opus 5.5 | Interactively, in 50 batches of 20 records with the same prompt; snippets over 150 lines shown as their first 110 and last 40 lines (`judge_view.py`). `judging_notes.md` lists the conventions applied to borderline cases |
| `deepseek-v4-flash-0731/` | DeepSeek-V4-Flash (0731) via OpenRouter | `run_judge.py` (needs `OPENROUTER_API_KEY`), one record per request, temperature 0; cost in `cost.json` |
| `gpt-oss-120b/` | gpt-oss-120b, served locally with vLLM 0.30 on one A100 | `run_judge.py`, one record per request, temperature 0, medium reasoning effort |

Each judge folder holds `verdicts.jsonl` (its labels) and `results.json` (its rates, written by
`check_verdicts.py`). Raw API responses are not included; the verdicts are parsed from them unchanged.

## Files

| File | What it is |
|---|---|
| `make_sample.py` | Draws the sample (1,000 records, seed 0, in proportion to the two sources) and writes `batches/`, the 50 batches of 20 records exactly as given to the Claude judge (regenerated identically, so not stored) |
| `sample_records.json` | The 1,000 sampled records as the judges saw them (4,595 pairs) |
| `prompt.md` | The judge prompt: labels, definitions, output format |
| `judge_view.py` | Renders records for a judge, as given to Claude |
| `check_verdicts.py` | Validates a judge's `verdicts.jsonl` and writes its `results.json` |
| `summarize_judges.py` | Majority vote, agreement (Cohen's and Fleiss' κ) and bootstrap intervals → `summary.json`, `majority_verdicts.jsonl` |
| `by_topic.py` | Majority rates by question topic → `by_topic.json` |
| `compare_annotators.py` | Detailed agreement between two judges → `agreement_<A>__<B>.json` |

To recompute every number from the included verdicts:

```
python hallucination_analysis/summarize_judges.py claude-opus-5-5 deepseek-v4-flash-0731 gpt-oss-120b
python hallucination_analysis/by_topic.py
```

## Format

Each line of a judge's `verdicts.jsonl` is one record:

```json
{"record_id": "cvefixes_4543", "cve_id": "CVE-2014-125039", "source": "cvefixes", "language": "JavaScript/TypeScript",
 "annotator": "claude-opus-5-5",
 "verdicts": [{"pair_id": "cvefixes_4543#1", "question_relevant": true, "support": "supported",
               "answerable_from_code": false, "error_type": null, "reason": "..."}, ...]}
```

`majority_verdicts.jsonl` gives, per pair, each judge's support label, the number of judges that
labelled it hallucinated, and the majority labels; join it with the dataset by `pair_id`.

Labels per pair:

- `support`: `supported`, `partly_supported`, `unsupported` or `contradicted`, against the description
  and the code. **Hallucinated** means unsupported or contradicted.
- `answerable_from_code`: the question can be answered from the snippet alone, without the description.
- `error_type` (pairs that are not supported): wrong_location, invented_identifier,
  wrong_vulnerability_type, wrong_mechanism, wrong_impact, wrong_version_or_product,
  unfounded_severity, inapplicable_fix, generic_or_evasive, other.
- `question_relevant`: the question concerns the vulnerability or the code (99.9% or more for every
  judge).

Intervals are 95% bootstrap intervals that resample records, since pairs of the same record are not
independent.

## Adding a judge

Create `<judge-name>/`, give the judge `prompt.md` and the records (`judge_view.py` renders them), save
its output in the format above as `verdicts.jsonl`, run `check_verdicts.py <judge-name>`, and add it to
the `summarize_judges.py` command. A human annotation of the sample would be a welcome addition.
