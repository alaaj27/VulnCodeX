# VulnCodeX data

`vulncodex.jsonl.gz` holds the whole dataset: 26,003 records, one JSON object per line. Every split in
`splits/` is a list of record ids into this file.

| | |
|---|---|
| Records (vulnerable functions with a conversation) | 26,003 |
| Question–answer pairs | 119,118 |
| CVEs | 6,911 |
| Programming languages | 10 (C, PHP, C++, JavaScript/TypeScript, Java, Python, Ruby, Go, C#, Rust) |
| Sources | CVEfixes (19,127 records), Big-Vul (6,876 records) |

## Record format

```json
{
  "id": "cvefixes_29108",
  "source": "CVEfixes",
  "cve_id": "CVE-2019-13574",
  "language": "Ruby",
  "description": "In lib/mini_magick/image.rb in MiniMagick before 4.9.4, a fetched remote image filename could cause remote command execution because Image.open input is directly passed to Kernel#open, ...",
  "code": "def self.open(path_or_url, ext = nil, options = {}) ...",
  "conversations": [
    {"from": "human", "value": "<code_sequence>\nWhat is the vulnerability in the code?"},
    {"from": "gpt",   "value": "The vulnerability is a remote command execution vulnerability in the MiniMagick library, ..."},
    {"from": "human", "value": "What is the root cause of the vulnerability?"},
    {"from": "gpt",   "value": "The root cause of the vulnerability is the direct passing of the input path_or_url to Kernel#open, ..."}
  ],
  "question_topics": ["Vuln. type", "Mechanism"]
}
```

| Field | Meaning |
|---|---|
| `id` | Unique record id. The prefix gives the source: `cvefixes_` or `msr_` (Big-Vul, also known as the MSR 2020 dataset) |
| `source` | `CVEfixes` or `Big-Vul` |
| `cve_id` | CVE identifier of the vulnerability |
| `language` | Programming language, predicted from the code (estimated 98.8% correct; see `pipeline/README.md`) |
| `description` | The CVE description the conversation was generated from |
| `code` | The vulnerable (pre-fix) function |
| `conversations` | Alternating `human` (question) and `gpt` (answer) turns, at least two pairs. The first question starts with the `<code_sequence>` placeholder, which marks where the code goes when the data is used for training |
| `question_topics` | One topic per question–answer pair, from the keyword rules in `vulncodex/topics.py` |

A pair is identified as `<record id>#<k>`, with k = 1, 2, … in conversation order. The benchmark and
hallucination-analysis files use these pair ids.

## Loading

No dependencies beyond the Python standard library:

```python
from vulncodex import load_records, load_split, pairs

records = load_records()                     # all 26,003 records
test = load_split("cve", "test")             # the main test split of the paper
for pair_id, question, answer, topic in pairs(test[0]):
    print(pair_id, topic, question)
```

`splits/README.md` explains every split. If unsure, use `cve`: no CVE and no code snippet occurs in
more than one of its train, validation and test splits.

## Question topics

| Topic | Questions | Most frequent question |
|---|---|---|
| Vuln. type | 25,697 | What is the vulnerability in the given code? |
| Fix | 23,988 | How can this vulnerability be fixed? |
| Location | 16,773 | Where in the code is the vulnerability located? |
| Mechanism | 15,245 | How does the vulnerability work? |
| Impact | 11,111 | What is the impact of this vulnerability? |
| Exploitation | 7,380 | How can this vulnerability be exploited? |
| Affected software | 5,259 | What is the affected function in the code? |
| Code behaviour | 3,879 | What is the purpose of the code snippet provided? |
| Severity | 2,191 | What is the severity of this vulnerability? |
| Other | 7,595 | Which parameter is vulnerable to SQL injection? (no rule matched) |

## Reliability of the answers

The answers were written by Llama-3.1-8B-Instruct from the code and the CVE description, then filtered
with explicit rules (`pipeline/`). Three LLM judges from other model families checked a sample of 1,000
records (`hallucination_analysis/`): 85.2% of the answers are supported or partly supported by the
description or the code. The unsupported answers are concentrated in a few topics, so they can be
handled by topic:

- **Severity** answers are often invented (CVE descriptions rarely state a severity). We recommend
  dropping severity questions for training, as the paper's fine-tuning does.
- **Location** and **Fix** answers are the next most error-prone; weight them lower if needed.
- **Vuln. type, Mechanism, Impact** answers are rarely unsupported (2–6%).

Every snippet is vulnerable (the pre-fix version), so the data does not cover patched code.

## Licence

CC BY 4.0 (see `../DATA_LICENSE`), with attribution to CVEfixes (CC BY 4.0) and Big-Vul (MIT, Copyright
(c) 2020 ZeoVan). The question–answer pairs were generated with Llama 3.1 and carry its notice; a model
trained on this data and made available must have a name that begins with "Llama" (see `../NOTICE`).
