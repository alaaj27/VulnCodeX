"""Clean the fine-tuning dataset and write it to a new file.

Usage:  python pipeline/clean_dataset.py
Reads:  work/raw/generated.json   (left untouched)
Writes: work/clean/clean.json
        pipeline/reports/cleaning_report.json   (how many records / pairs each rule removed)

Rules, in order (see pipeline/reports/flaw_examples.txt for examples of each flaw):
  record  snippet under 20 characters
  record  snippet is a slice of minified code
  record  conversation does not alternate human/gpt
  record  an answer says the whole snippet is unrelated to the vulnerability
  pair    blank or None question or answer; a trailing unanswered question is dropped
  pair    answer repeats the question, refusal, question already asked in the record
  pair    answer says a detail is not shown in the snippet
  pair    answer only says the information is not available
  pair    question or answer cites "the description" or "the provided information"
  record  first pair was removed, or fewer than MIN_PAIRS pairs are left
  record  same ID as another record (the one with more pairs is kept), exact duplicate
  record  over MAX_PER_CVE records for one CVE
The content rules are regex heuristics.
"""
import collections
import json
import random
import re
from pathlib import Path

from show_flaw_examples import (DESCRIPTION, NON_ANSWER, PLACEHOLDER, REFUSAL, UNRELATED, BLANKS,
                                is_minified)

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'work' / 'raw' / 'generated.json'
OUT = ROOT / 'work' / 'clean' / 'clean.json'
REPORT = ROOT / 'pipeline' / 'reports' / 'cleaning_report.json'
MIN_CODE_CHARS = 20
MIN_PAIRS = 2
MAX_PER_CVE = 200
SEED = 0

# An answer that says the snippet as a whole does not relate to / contain the vulnerability.
# Narrower than UNRELATED, which also matches "the specific line is not shown".
SNIPPET_UNRELATED = re.compile(
    r"(?i)(code|snippet|function|file)\b[^.]{0,40}\b(is not|isn't|are not|does not (seem|appear) to be"
    r"|doesn't (seem|appear) to be|not (directly |explicitly )?)\s*(directly |explicitly )?(related|relevant)"
    r"|not (directly )?(related|relevant) to the (given|provided) (source )?(code|snippet)"
    r"|unrelated to the"
    r"|no (\w+ ){0,3}vulnerabilit\w+ in (the|this) (given|provided)?\s*(source )?(code|snippet)"
    r"|(code|snippet)[^.]{0,30}does not contain (any|the|a)\b[^.]{0,30}vulnerab"
    r"|vulnerability (is not|does not occur|is not (present|located|found)) in the (given|provided)"
    r"|none of the (provided |given )?(source )?(code|lines)[^.]{0,40}(related|relevant|vulnerable)")
# Answers that lean on the generation prompt rather than on the snippet.
PROMPT_REFERENCE = re.compile(r"(?i)\b(provided|given) (information|text|context)\b")


def clean_text(text):
    """Strip whitespace, turn escaped quotes into quotes and drop a stray quote at either end.

    Escaped newlines are left alone: they mostly occur inside quoted code, where they are literal.
    """
    text = re.sub(r'\\+"', '"', text).strip()
    if text.count('"') % 2 == 1:
        if text.endswith('"'):
            text = text[:-1].rstrip()
        elif text.startswith('"'):
            text = text[1:].lstrip()
    return text


def is_blank(text):
    return text.lower() in BLANKS


def to_pairs(turns):
    """(question, answer) pairs; a trailing unanswered question is dropped."""
    return [(clean_text(turns[i]['value'].replace(PLACEHOLDER, '')), clean_text(turns[i + 1]['value']))
            for i in range(0, len(turns) - 1, 2)]


def pair_flaw(question, answer, asked):
    if is_blank(question) or is_blank(answer):
        return 'blank or None'
    if question.lower() == answer.lower():
        return 'answer repeats the question'
    if REFUSAL.search(answer):
        return 'refusal'
    if UNRELATED.search(answer):
        return 'answer says a detail is not shown in the snippet'
    if NON_ANSWER.search(answer):
        return 'answer only says the information is not available'
    if DESCRIPTION.search(question) or DESCRIPTION.search(answer) or PROMPT_REFERENCE.search(answer):
        return 'cites "the description"'
    if question.lower() in asked:
        return 'question already asked in the record'
    return None


def to_conversation(pairs):
    turns = []
    for i, (question, answer) in enumerate(pairs):
        turns.append({'from': 'human', 'value': (PLACEHOLDER + '\n' if i == 0 else '') + question})
        turns.append({'from': 'gpt', 'value': answer})
    return turns


def cap_per_cve(records, rng):
    """Keep at most MAX_PER_CVE records per CVE, taking one record per distinct snippet first."""
    by_cve = collections.defaultdict(list)
    for r in records:
        by_cve[r['cve_id']].append(r)
    keep = set()
    for group in by_cve.values():
        if len(group) > MAX_PER_CVE:
            rng.shuffle(group)
            seen, first, rest = set(), [], []
            for r in group:
                (rest if r['code'] in seen else first).append(r)
                seen.add(r['code'])
            group = (first + rest)[:MAX_PER_CVE]
        keep.update(id(r) for r in group)
    return [r for r in records if id(r) in keep]


def main():
    with open(DATA) as f:
        records = json.load(f)
    dropped_records = collections.Counter()
    dropped_pairs = collections.Counter()
    pairs_in = sum(len(r['conversations']) // 2 for r in records)

    kept = []
    for r in records:
        turns = r['conversations']
        if len(r['code'].strip()) < MIN_CODE_CHARS:
            dropped_records['snippet under 20 characters'] += 1
            continue
        if is_minified(r['code']):
            dropped_records['snippet is a slice of minified code'] += 1
            continue
        if any(t['from'] != ('human' if i % 2 == 0 else 'gpt') for i, t in enumerate(turns)):
            dropped_records['conversation does not alternate human/gpt'] += 1
            continue
        pairs = to_pairs(turns)
        if any(SNIPPET_UNRELATED.search(a) for _, a in pairs):
            dropped_records['an answer says the whole snippet is unrelated'] += 1
            continue
        good, asked, first_removed = [], set(), False
        for i, (question, answer) in enumerate(pairs):
            flaw = pair_flaw(question, answer, asked)
            if flaw:
                dropped_pairs[flaw] += 1
                first_removed = first_removed or i == 0
                continue
            asked.add(question.lower())
            good.append((question, answer))
        if first_removed:
            dropped_records['first pair was removed'] += 1
            continue
        if len(good) < MIN_PAIRS:
            dropped_records[f'fewer than {MIN_PAIRS} pairs left'] += 1
            continue
        kept.append({'id': r['id'], 'cve_id': r['cve_id'], 'code': r['code'],
                     'conversations': to_conversation(good)})

    # One record per ID: the one with the most pairs (the first one on a tie).
    best = {}
    for r in kept:
        if r['id'] not in best or len(r['conversations']) > len(best[r['id']]['conversations']):
            best[r['id']] = r
    dropped_records['same ID as another record'] = len(kept) - len(best)
    kept = [r for r in kept if best[r['id']] is r]

    seen, unique = set(), []
    for r in kept:
        key = (r['code'], r['cve_id'], json.dumps(r['conversations']))
        if key not in seen:
            seen.add(key)
            unique.append(r)
    dropped_records['exact duplicate under another ID'] = len(kept) - len(unique)
    kept = unique

    capped = cap_per_cve(kept, random.Random(SEED))
    dropped_records[f'over {MAX_PER_CVE} records for one CVE'] = len(kept) - len(capped)
    kept = capped

    assert len({r['id'] for r in kept}) == len(kept)
    with open(OUT, 'w') as f:
        json.dump(kept, f, indent=4)

    pairs_out = sum(len(r['conversations']) // 2 for r in kept)
    report = {
        'input': {'file': DATA.name, 'records': len(records), 'pairs': pairs_in,
                  'cves': len({r['cve_id'] for r in records})},
        'output': {'file': OUT.name, 'records': len(kept), 'pairs': pairs_out,
                   'cves': len({r['cve_id'] for r in kept}),
                   'by_source': dict(collections.Counter(r['id'].split('_')[0] for r in kept))},
        'records_dropped': dict(dropped_records),
        'pairs_dropped': dict(dropped_pairs),
    }
    REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    print('wrote', OUT)
    print('wrote', REPORT)


if __name__ == '__main__':
    main()
