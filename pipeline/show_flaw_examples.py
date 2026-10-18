"""Show examples of each flaw found in the fine-tuning dataset.

Usage:  python pipeline/show_flaw_examples.py [examples_per_flaw]
Reads:  work/raw/generated.json
Writes: pipeline/reports/flaw_examples.txt

The content rules (flaws 1-4) are regex heuristics, so their counts are approximate.
"""
import collections
import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'work' / 'raw' / 'generated.json'
OUT = ROOT / 'pipeline' / 'reports' / 'flaw_examples.txt'
PLACEHOLDER = '<code_sequence>'
N_EXAMPLES = int(sys.argv[1]) if len(sys.argv) > 1 else 3
CODE_PREVIEW = 300
TEXT_PREVIEW = 400
SEED = 0

# An answer that says the snippet does not relate to / contain the vulnerability.
UNRELATED = re.compile(
    r"(?i)(code|snippet|source|function|file)[^.]{0,60}(not|n't|no)[^.]{0,30}"
    r"(related|relevant|contain|show|include|appear|seem|relation|connection|part of)"
    r"|not (directly |explicitly )?(related|relevant) to the (given|provided|this)"
    r"|unrelated to the|no (code|line)[^.]{0,50}related"
    r"|not (present|located|found|shown|included) in the (given|provided)")
# An answer that only says the information is not available.
NON_ANSWER = re.compile(
    r"(?i)(not|n't|no)\b[^.]{0,60}\b(provided|mentioned|specified|available|described|stated|given"
    r"|information|clear|explicit|details?|indicat|provide|specify|mention)"
    r"|\b(unknown|unclear|cannot be determined)\b|^unfortunately")
DESCRIPTION = re.compile(r'(?i)\bdescription\b')
REFUSAL = re.compile(r"(?i)^I (cannot|can't) (provide|help|assist)|anything else I can help")
ESCAPES = re.compile(r'\\+["n\']')
BLANKS = ('', 'none', 'null', 'nan', 'n/a')


def text_of(turn):
    return turn['value'].replace(PLACEHOLDER, '').strip()


def is_blank(turn):
    return text_of(turn).lower() in BLANKS


def is_minified(code):
    lines = code.split('\n')
    return max(len(l) for l in lines) > 500 or (len(lines) == 1 and len(code) > 200)


def clip(text, limit):
    text = text.replace('\n', '\\n')
    return text if len(text) <= limit else text[:limit] + f' ...[{len(text) - limit} more chars]'


def answers(record):
    return [(i, t) for i, t in enumerate(record['conversations']) if t['from'] == 'gpt']


def questions(record):
    return [(i, t) for i, t in enumerate(record['conversations']) if t['from'] == 'human']


class Report:
    def __init__(self, records):
        self.records = records
        self.lines = []
        self.rng = random.Random(SEED)

    def write(self, line=''):
        self.lines.append(line)

    def header(self, number, title, summary):
        self.write()
        self.write('=' * 100)
        self.write(f'FLAW {number}: {title}')
        self.write(summary)
        self.write('=' * 100)

    def record(self, index, turns=None, code=True, mark=()):
        """Print one record; `turns` limits which turn indexes are shown, `mark` flags the flawed ones."""
        r = self.records[index]
        self.write(f'  [{r["id"]} | {r["cve_id"]} | record #{index} | {len(r["conversations"])} turns]')
        if code:
            self.write(f'    code ({len(r["code"])} chars, {r["code"].count(chr(10)) + 1} lines): '
                       f'{clip(r["code"], CODE_PREVIEW)}')
        for i, t in enumerate(r['conversations']):
            if turns is not None and i not in turns:
                continue
            flag = '>>' if i in mark else '  '
            self.write(f'  {flag} {i:2d} {t["from"]:5s}: {clip(t["value"], TEXT_PREVIEW)}')
        self.write()

    def sample(self, items):
        return self.rng.sample(items, min(N_EXAMPLES, len(items)))


def pair_with_question(index):
    """Turn indexes of an answer and the question before it."""
    return {index - 1, index}


def main():
    with open(DATA) as f:
        records = json.load(f)
    n = len(records)
    rep = Report(records)
    rep.write(f'Flaw examples for {DATA.name}')
    rep.write(f'{n:,} records, {N_EXAMPLES} examples per flaw (random seed {SEED}).')
    rep.write('Lines marked >> are the turns that show the flaw. Long text is clipped.')

    # 1. minified code slices
    hits = [i for i, r in enumerate(records) if is_minified(r['code'])]
    cves = {records[i]['cve_id'] for i in hits}
    rep.header(1, 'Snippet is a slice of minified code',
               f'{len(hits):,} records ({100 * len(hits) / n:.1f}%) from {len(cves)} CVEs. '
               'Rule: a line over 500 chars, or a single line over 200 chars.')
    for i in rep.sample(hits):
        rep.record(i, turns={0, 1})

    # 2. answer says the snippet is unrelated
    hits = []
    for i, r in enumerate(records):
        marked = [j for j, t in answers(r) if UNRELATED.search(t['value'])]
        if marked:
            hits.append((i, marked))
    rep.header(2, 'An answer says the snippet is unrelated to the vulnerability',
               f'{len(hits):,} records ({100 * len(hits) / n:.1f}%).')
    for i, marked in rep.sample(hits):
        shown = {0, 1} | set().union(*(pair_with_question(j) for j in marked))
        rep.record(i, turns=shown, mark=marked)

    # 3. non-answers
    hits = [(i, j) for i, r in enumerate(records) for j, t in answers(r)
            if NON_ANSWER.search(t['value']) and not UNRELATED.search(t['value'])]
    total_answers = sum(len(answers(r)) for r in records)
    rep.header(3, 'Non-answers (the answer only says the information is not available)',
               f'{len(hits):,} answers ({100 * len(hits) / total_answers:.1f}% of answers), '
               'not counting the "unrelated" answers of flaw 2.')
    for i, j in rep.sample(hits):
        rep.record(i, turns=pair_with_question(j), code=False, mark=[j])

    # 4. references to "the description"
    hits_a = [(i, j) for i, r in enumerate(records) for j, t in answers(r) if DESCRIPTION.search(t['value'])]
    hits_q = [(i, j) for i, r in enumerate(records) for j, t in questions(r) if DESCRIPTION.search(t['value'])]
    informative = [(i, j) for i, j in hits_a
                   if not NON_ANSWER.search(records[i]['conversations'][j]['value'])
                   and not UNRELATED.search(records[i]['conversations'][j]['value'])]
    rep.header(4, 'Turns cite "the description", which is not part of the model input',
               f'{len(hits_a):,} answers in {len({i for i, _ in hits_a}):,} records, and {len(hits_q):,} questions. '
               f'{len(informative):,} of the answers are otherwise informative.')
    rep.write('  -- answers that are otherwise informative --')
    for i, j in rep.sample(informative):
        rep.record(i, turns=pair_with_question(j), code=False, mark=[j])
    rep.write('  -- questions --')
    for i, j in rep.sample(hits_q):
        rep.record(i, turns={j, j + 1}, code=False, mark=[j])

    # 5. exact duplicates
    groups = collections.defaultdict(list)
    for i, r in enumerate(records):
        groups[(r['code'], json.dumps(r['conversations'], sort_keys=True))].append(i)
    dup_groups = [g for g in groups.values() if len(g) > 1]
    surplus = sum(len(g) - 1 for g in dup_groups)
    rep.header(5, 'Exact duplicates (same snippet and same conversation)',
               f'{surplus:,} surplus copies in {len(dup_groups):,} groups.')
    for g in rep.sample(dup_groups):
        rep.write(f'  group of {len(g)} identical records: '
                  + ', '.join(f'#{i} ({records[i]["id"]})' for i in g))
        rep.record(g[0], turns={0, 1})

    # 6. reused record IDs
    by_id = collections.defaultdict(list)
    for i, r in enumerate(records):
        by_id[r['id']].append(i)
    reused = [g for g in by_id.values() if len(g) > 1]
    differing = [g for g in reused
                 if records[g[0]]['conversations'] != records[g[1]]['conversations']]
    rep.header(6, 'Reused record IDs',
               f'{len(reused):,} IDs are used more than once ({len(by_id):,} distinct IDs for {n:,} records). '
               f'{len(differing):,} of them carry different conversations.')
    for g in rep.sample(differing):
        rep.write(f'  ID {records[g[0]]["id"]} appears {len(g)} times: records ' + ', '.join(f'#{i}' for i in g))
        for i in g[:2]:
            rep.record(i, turns={0, 1, 2, 3}, code=(i == g[0]))

    # 7. same snippet labelled with several CVEs
    cves_of = collections.defaultdict(set)
    index_of = collections.defaultdict(list)
    for i, r in enumerate(records):
        cves_of[r['code']].add(r['cve_id'])
        index_of[r['code']].append(i)
    multi = [c for c, s in cves_of.items() if len(s) > 1]
    rep.header(7, 'Same snippet labelled with several CVEs',
               f'{len(multi):,} snippets in {sum(len(index_of[c]) for c in multi):,} records; '
               f'at most {max(len(s) for s in cves_of.values())} CVEs for one snippet.')
    for c in rep.sample(multi):
        rep.write(f'  snippet used by {len(index_of[c])} records with {len(cves_of[c])} CVEs: '
                  + ', '.join(sorted(cves_of[c])))
        rep.write(f'    code: {clip(c, CODE_PREVIEW)}')
        seen = set()
        for i in index_of[c]:
            if records[i]['cve_id'] not in seen and len(seen) < 3:
                seen.add(records[i]['cve_id'])
                rep.write(f'    {records[i]["cve_id"]} ({records[i]["id"]}) first answer: '
                          f'{clip(records[i]["conversations"][1]["value"], 200)}')
        rep.write()

    # 8. concentration on few CVEs
    per_cve = collections.Counter(r['cve_id'] for r in records)
    unrelated_per_cve = collections.Counter(
        r['cve_id'] for r in records if any(UNRELATED.search(t['value']) for _, t in answers(r)))
    minified_per_cve = collections.Counter(r['cve_id'] for r in records if is_minified(r['code']))
    snippets_per_cve = collections.defaultdict(set)
    for r in records:
        snippets_per_cve[r['cve_id']].add(r['code'])
    big = [c for c, k in per_cve.items() if k > 1000]
    rep.header(8, 'Records are concentrated on a few CVEs',
               f'{len(big)} CVEs with more than 1,000 records hold '
               f'{100 * sum(per_cve[c] for c in big) / n:.1f}% of all records.')
    rep.write(f'  {"CVE":16s} {"records":>8s} {"snippets":>9s} {"minified":>9s} {"flagged unrelated":>18s}')
    for c, k in per_cve.most_common(len(big)):
        rep.write(f'  {c:16s} {k:8,d} {len(snippets_per_cve[c]):9,d} '
                  f'{100 * minified_per_cve[c] / k:8.0f}% {100 * unrelated_per_cve[c] / k:17.0f}%')
    rep.write()
    top = per_cve.most_common(1)[0][0]
    rep.write(f'  -- records of the largest CVE ({top}) --')
    for i in rep.sample([i for i, r in enumerate(records) if r['cve_id'] == top]):
        rep.record(i, turns={0, 1, 2, 3})

    # 9. literal escape sequences
    hits = [(i, j) for i, r in enumerate(records) for j, t in enumerate(r['conversations'])
            if ESCAPES.search(t['value'])]
    rep.header(9, 'Literal escape sequences in the text (backslash-quote, backslash-n)',
               f'{len(hits):,} turns in {len({i for i, _ in hits}):,} records.')
    for i, j in rep.sample(hits):
        rep.record(i, turns={j}, code=False, mark=[j])

    # 10. blank or None turns
    blank_q = [(i, j) for i, r in enumerate(records) for j, t in questions(r) if is_blank(t)]
    blank_a = [(i, j) for i, r in enumerate(records) for j, t in answers(r) if is_blank(t)]
    trailing = sum(1 for i, j in blank_q if j == len(records[i]['conversations']) - 1)
    rep.header(10, 'Blank or None turns',
               f'{len(blank_q):,} questions ({trailing:,} of them are the last turn of the record) and '
               f'{len(blank_a):,} answers, in {len({i for i, _ in blank_q + blank_a}):,} records.')
    rep.write('  -- blank questions --')
    for i, j in rep.sample(blank_q):
        rep.record(i, turns={j - 2, j - 1, j, j + 1}, code=False, mark=[j])
    rep.write('  -- blank answers --')
    for i, j in rep.sample(blank_a):
        rep.record(i, turns={j - 1, j, j + 1}, code=False, mark=[j])

    # 11. broken turn order
    hits = []
    for i, r in enumerate(records):
        marked = [j for j, t in enumerate(r['conversations'])
                  if t['from'] != ('human' if j % 2 == 0 else 'gpt')]
        if marked:
            hits.append((i, marked[0]))
    unanswered = [i for i, r in enumerate(records)
                  if r['conversations'][-1]['from'] == 'human' and not is_blank(r['conversations'][-1])]
    rep.header(11, 'Broken turn order',
               f'{len(hits)} records do not alternate human/gpt; '
               f'{len(unanswered)} records end on a real (non-blank) unanswered question.')
    rep.write('  -- two questions in a row --')
    for i, j in rep.sample(hits):
        rep.record(i, turns={j - 2, j - 1, j, j + 1}, code=False, mark=[j - 1, j])
    rep.write('  -- ends on an unanswered question --')
    for i in rep.sample(unanswered):
        last = len(records[i]['conversations']) - 1
        rep.record(i, turns={last - 2, last - 1, last}, code=False, mark=[last])

    # 12. small items
    same, repeated, refusals, tiny = [], [], [], []
    for i, r in enumerate(records):
        turns = r['conversations']
        seen = {}
        for j, t in enumerate(turns):
            if t['from'] == 'gpt':
                if REFUSAL.search(t['value']):
                    refusals.append((i, j))
                if j and not is_blank(t) and text_of(turns[j - 1]).lower() == text_of(t).lower():
                    same.append((i, j))
            elif not is_blank(t):
                key = text_of(t).lower()
                if key in seen:
                    repeated.append((i, seen[key], j))
                seen.setdefault(key, j)
        if len(r['code'].strip()) < 20:
            tiny.append(i)
    rep.header(12, 'Small items',
               f'{len(same)} pairs where the answer repeats the question, '
               f'{len({i for i, _, _ in repeated})} records that ask the same question twice, '
               f'{len(refusals)} refusals, {len(tiny)} snippets under 20 characters.')
    rep.write('  -- answer repeats the question --')
    for i, j in rep.sample(same):
        rep.record(i, turns={j - 1, j}, code=False, mark=[j])
    rep.write('  -- same question asked twice --')
    for i, first, second in rep.sample(repeated):
        rep.record(i, turns={first, first + 1, second, second + 1}, code=False, mark=[first, second])
    rep.write('  -- refusals --')
    for i, j in rep.sample(refusals):
        rep.record(i, turns={j - 1, j}, code=False, mark=[j])
    rep.write('  -- snippets under 20 characters --')
    for i in rep.sample(tiny):
        rep.record(i, turns={0, 1})

    OUT.write_text('\n'.join(rep.lines) + '\n')
    print('wrote', OUT, f'({len(rep.lines)} lines)')


if __name__ == '__main__':
    main()
