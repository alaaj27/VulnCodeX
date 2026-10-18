# Pipeline: building VulnCodeX

How the released dataset is made from the generation output (paper Section III and Appendices A–C).
Run the steps from the repository root, in this order. Inputs and intermediate files live in `work/`
(not in the repository); small reports that document each step are in `pipeline/reports/`.

| Step | Script | Reads | Writes |
|---|---|---|---|
| 1. Filter | `clean_dataset.py` | `work/raw/generated.json` | `work/clean/clean.json`, `reports/cleaning_report.json` |
| 2. Detect languages | `detect_languages.py` (GPU optional) | `work/clean/clean.json` | `reports/record_languages.json` |
| 3. Add languages | `add_languages.py` | step 1 and 2 outputs | `work/clean/clean_lang.json` |
| 4. Add CVE descriptions | `add_descriptions.py` | `work/clean/clean_lang.json`, `work/raw/cvefixes_descriptions.csv`, `work/raw/bigvul.csv` | `work/clean/vulncodex_v3.json`, `reports/descriptions_report.json` |
| 5. Split | `make_splits.py` | `work/clean/vulncodex_v3.json` | `data/splits/` |
| 6. Release file | `export_release.py` | `work/clean/vulncodex_v3.json` | `data/vulncodex.jsonl.gz` |
| Check languages | `validate_languages.py` | step 4 output, source labels, `language_validation/` | `reports/language_validation.json` |
| Examples of each flaw | `show_flaw_examples.py` | `work/raw/generated.json` | `reports/flaw_examples.txt` |

Steps 1, 3, 4, 5 and 6 are deterministic: run on the generation output, they rebuild the released
dataset and splits byte for byte (checked). Step 2 runs a classifier and is included for completeness;
its output is `reports/record_languages.json`.

## Inputs

- `work/raw/generated.json`: the output of the generation step, 110,817 records with 540,654
  question–answer pairs, written by Llama-3.1-8B-Instruct with the prompt in `generation_prompt.md`.
  It will be published with the dataset on Hugging Face (raw files).
- `work/raw/cvefixes_descriptions.csv` and `work/raw/bigvul.csv`: the CVE descriptions (and source
  language labels) of CVEfixes and Big-Vul, keyed by the source's code id.

## Filtering rules

`clean_dataset.py` applies the rules below in order; the patterns are in `show_flaw_examples.py`, the
counts in `reports/cleaning_report.json`, and an example of every flaw in `reports/flaw_examples.txt`.

| Level | Rule |
|---|---|
| record | snippet under 20 characters |
| record | snippet is a slice of minified code (a line over 500 characters, or a single line over 200) |
| record | conversation does not alternate question and answer |
| record | an answer says the snippet is unrelated to the vulnerability or does not contain it |
| pair | empty question or answer; a trailing unanswered question is dropped |
| pair | answer repeats the question, refusal, or question already asked in the record |
| pair | answer says a detail is not shown in the snippet |
| pair | answer only says the information is not available |
| pair | question or answer cites "the description" or "the provided information" |
| record | the first pair was removed, or fewer than two pairs are left |
| record | same id as another record (the one with more pairs is kept), or exact duplicate |
| record | more than 200 records for one CVE (sampled at random, preferring distinct snippets) |

The filters keep 23.5% of the generated records but 92.0% of the CVEs: most of the removed records come
from a few very large commits.

## Languages

The sources carry no reliable per-file language, so `detect_languages.py` predicts it from the code
with a CodeBERTa-based classifier, plus syntax rules that separate C, C++ and C#. `validate_languages.py`
compares the predictions with the source labels and estimates their accuracy from a hand-checked sample
of 150 disagreements (`language_validation/disagreements_adjudicated.csv`): 98.8% (95% CI 97.9–99.2%).
`language_validation/record_languages_v1.json` is the first version of the labels, from which that
sample was drawn.
