"""Detect the programming language of every snippet in the cleaned dataset.

Usage:  python pipeline/detect_languages.py
Reads:  work/clean/clean.json
Writes: pipeline/reports/record_languages.json   {record id: {"language", "model_language", "confidence"}}

The dataset carries no language label, so the language is predicted from the code with a
CodeBERTa-based classifier (MODEL, 26 languages) and then corrected with three rules:
  * The model confuses C, C++ and C# with each other. Within this family the choice is made by
    syntax: C# only when the model is very sure, otherwise C++ if the snippet uses C++-only
    syntax, otherwise C. A C++ function that uses no C++-only syntax is therefore counted as C.
    The syntax is searched with comments and string literals removed, since C comments often
    contain words like "virtual" or "::", as a check against the source labels showed).
  * MSR (Big-Vul) contains only C and C++ projects, so MSR snippets always get one of the two.
  * Outside the C family, predictions below MIN_CONFIDENCE become "Other"; for languages that
    are rare in the data the bar is RARE_MIN_CONFIDENCE, because most of their low-confidence
    hits are mislabelled TypeScript or Ruby.
The model was trained without TypeScript and labels it as JavaScript, so both are reported as
"JavaScript/TypeScript".
"""
import collections
import json
import re
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'work' / 'clean' / 'clean.json'
OUT = ROOT / 'pipeline' / 'reports' / 'record_languages.json'
MODEL = 'philomath-1209/programming-language-identification'
MIN_CONFIDENCE = 0.5
RARE_MIN_CONFIDENCE = 0.9
CSHARP_MIN_CONFIDENCE = 0.9
C_FAMILY = {'C', 'C++', 'C#'}
COMMON = {'PHP', 'JavaScript', 'Java', 'Python', 'Ruby', 'Go', 'Rust'}
# Syntax that C does not have. Kept strict: C code uses "new", "class" or "&" in other ways.
CPP_SYNTAX = re.compile(r'::|\btemplate\s*<|\bclass\s+\w+\s*[:{]|\bnamespace\s+\w+\s*\{'
                        r'|\b(nullptr|constexpr)\b|\)\s*(const\s*)?override\b|\bvirtual\s+\w'
                        r'|\bnew\s+[A-Za-z_][\w:<>]*\s*[(\[;]|\bdelete\s*(\[\]\s*)?\w+\s*;|\bthis->'
                        r'|\b(static|dynamic|reinterpret|const)_cast\s*<'
                        r'|\bconst\s+[\w:<>]+\s*&\s*\w*\s*[,)]|\bTEST(_[FP])?\s*\(')
# Syntax that C# does not normally have; used to reject C++ that the model calls C#.
NOT_CSHARP_SYNTAX = re.compile(r'->|::|\bTEST(_[FP])?\s*\(')
# Comments and string or character literals, removed before the syntax rules are applied.
COMMENTS_AND_STRINGS = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])\'', re.S)
BATCH_SIZE = 64
MAX_TOKENS = 512
RENAME = {'JavaScript': 'JavaScript/TypeScript'}


def classify(snippets):
    """Return {snippet: (label, confidence)} for a list of distinct snippets."""
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    tokenizer = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL).to(device).eval()
    # sort by length so that each batch pads to a similar size
    order = sorted(snippets, key=len)
    result = {}
    with torch.no_grad():
        for start in range(0, len(order), BATCH_SIZE):
            batch = order[start:start + BATCH_SIZE]
            inputs = tokenizer(batch, truncation=True, max_length=MAX_TOKENS, padding=True,
                               return_tensors='pt').to(device)
            probs = model(**inputs).logits.softmax(dim=-1)
            confidence, index = probs.max(dim=-1)
            for snippet, c, i in zip(batch, confidence.tolist(), index.tolist()):
                result[snippet] = (model.config.id2label[i], c)
    return result


def final_language(label, confidence, code, is_msr):
    if is_msr or label in C_FAMILY:
        code = COMMENTS_AND_STRINGS.sub(' ', code)
        if (label == 'C#' and confidence >= CSHARP_MIN_CONFIDENCE and not is_msr
                and not NOT_CSHARP_SYNTAX.search(code)):
            return 'C#'
        return 'C++' if CPP_SYNTAX.search(code) else 'C'
    if confidence < (MIN_CONFIDENCE if label in COMMON else RARE_MIN_CONFIDENCE):
        return 'Other'
    return RENAME.get(label, label)


def main():
    with open(DATA) as f:
        records = json.load(f)
    predictions = classify(sorted({r['code'] for r in records}))
    out = {}
    for r in records:
        label, confidence = predictions[r['code']]
        language = final_language(label, confidence, r['code'], is_msr=r['id'].startswith('msr'))
        out[r['id']] = {'language': language, 'model_language': label, 'confidence': round(confidence, 4)}
    OUT.write_text(json.dumps(out, indent=1) + '\n')
    counts = collections.Counter(v['language'] for v in out.values())
    for language, count in counts.most_common():
        print(f'{language:24s} {count:6,d}  {100 * count / len(out):5.1f}%')
    print('wrote', OUT)


if __name__ == '__main__':
    main()
