"""Compute dataset statistics and emit LaTeX (a booktabs table and a pgfplots figure).

Usage:  python pipeline/make_dataset_stats.py
Reads:  data/vulncodex.jsonl.gz (written by add_descriptions.py)
        pipeline/reports/cleaning_report.json
        pipeline/reports/record_languages.json (written by detect_languages.py)
        hallucination_analysis/summary.json, sample_records.json (written by summarize_judges.py
        and make_sample.py; used for the hallucination-analysis band of the pipeline figure)
Writes: figures/out/pipeline_figure.tex (pipeline overview; counts come from cleaning_report.json
        and the hallucination-judge summary)
        figures/out/dataset_stats_figure.tex
        figures/out/dataset_stats_table.tex, dataset_stats_languages.tex (Tables II and III; the manuscript
        holds its own copy of each table)
        figures/out/prose_numbers.txt (every number quoted in the paper text, for checking)
        Then run scripts/export_figures.py to turn the figure sources into PDFs in paper/.
"""
import collections
import json
import re
from pathlib import Path

import numpy as np

import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from vulncodex import load_records  # noqa: E402
from vulncodex.topics import TOPIC_RULES, topic_of  # noqa: E402

REPORT = ROOT / 'pipeline' / 'reports' / 'cleaning_report.json'
LANGUAGES = ROOT / 'pipeline' / 'reports' / 'record_languages.json'
OUT_DIR = ROOT / 'figures' / 'out'
JUDGE_DIR = ROOT / 'hallucination_analysis'
# Display names of the hallucination judges, in the order they appear in summary.json.
JUDGE_NAMES = {'claude-opus-5-5': 'Claude Opus 5.5', 'deepseek-v4-flash-0731': 'DeepSeek-V4-Flash',
               'gpt-oss-120b': 'gpt-oss-120b'}
# Languages with a smaller share of the records than this are pooled into "Other".
MIN_LANGUAGE_SHARE = 0.003
PLACEHOLDER = '<code_sequence>'
SOURCES = [('msr', 'Big-Vul'), ('cvefixes', 'CVEfixes'), ('', 'All')]

def num(x):
    """Integer with LaTeX thousands separators."""
    return f'{int(round(x)):,}'.replace(',', '{,}')


def pct(part, whole, digits=1):
    return f'{100 * part / whole:.{digits}f}'


def question_text(turn):
    return turn['value'].replace(PLACEHOLDER, '').strip()




def source_stats(records):
    code_lines = np.array([r['code'].count('\n') + 1 for r in records])
    code_chars = np.array([len(r['code']) for r in records])
    turns = np.array([len(r['conversations']) for r in records])
    pairs = turns // 2
    q_words, a_words = [], []
    for r in records:
        for t in r['conversations']:
            if t['from'] == 'human':
                q_words.append(len(question_text(t).split()))
            else:
                a_words.append(len(t['value'].split()))
    q_words, a_words = np.array(q_words), np.array(a_words)
    conv_words = np.array([sum(len(t['value'].replace(PLACEHOLDER, '').split())
                               for t in r['conversations']) for r in records])
    per_code = collections.Counter(r['code'] for r in records)
    per_cve = np.array(sorted(collections.Counter(r['cve_id'] for r in records).values(), reverse=True))
    cves_per_code = collections.defaultdict(set)
    for r in records:
        cves_per_code[r['code']].add(r['cve_id'])
    n = len(records)
    return {
        'records': n,
        'unique_code': len(per_code),
        'unique_cves': len(per_cve),
        'pairs_total': int(pairs.sum()),
        'turns_total': int(turns.sum()),
        'lines': code_lines, 'chars': code_chars, 'pairs': pairs,
        'q_words': q_words, 'a_words': a_words, 'conv_words': conv_words,
        'single_line': int((code_lines == 1).sum()),
        'shared_code': sum(c for c in per_code.values() if c > 1),
        'multi_cve_code': sum(len(c) > 1 for c in cves_per_code.values()),
        'per_cve': per_cve,
        'top10_share': per_cve[:10].sum() / n,
    }


def med_mean_p95(x):
    return f'{np.median(x):.0f} / {x.mean():.1f} / {np.percentile(x, 95):.0f}'


def make_table(stats):
    cols = [stats[label] for _, label in SOURCES]

    def row(name, fn):
        return f'{name} & ' + ' & '.join(fn(s) for s in cols) + r' \\'

    lines = [
        r'% Requires: \usepackage{booktabs,colortbl} and the \grouprow macro of the paper preamble',
        r'\begin{table*}[t]',
        r'\centering',
        r'\small',
        r'\caption{Statistics of the cleaned dataset by source. Triples are median / mean / 95th'
        r' percentile; words are whitespace-separated tokens. A CVE can occur in both sources, so the'
        r' per-source CVE counts do not add up to the total.}',
        r'\label{tab:dataset-stats}',
        r'\begin{tabular}{lrrr}',
        r'\toprule',
        ' & ' + ' & '.join(r'\textbf{' + label + '}' for _, label in SOURCES) + r' \\',
        r'\midrule',
        r'\grouprow{4}{Size}',
        row('Records', lambda s: num(s['records'])),
        row('Distinct code snippets', lambda s: num(s['unique_code'])),
        row('Distinct CVEs', lambda s: num(s['unique_cves'])),
        row('Question--answer pairs', lambda s: num(s['pairs_total'])),
        r'\midrule',
        r'\grouprow{4}{Code snippet}',
        row('Lines', lambda s: med_mean_p95(s['lines'])),
        row(r'Single-line snippets (\%)', lambda s: pct(s['single_line'], s['records'])),
        r'\midrule',
        r'\grouprow{4}{Conversation}',
        row('Q--A pairs per record', lambda s: med_mean_p95(s['pairs'])),
        row('Words per answer', lambda s: med_mean_p95(s['a_words'])),
        r'\midrule',
        r'\grouprow{4}{Redundancy}',
        row(r'Records sharing a snippet (\%)', lambda s: pct(s['shared_code'], s['records'])),
        row('Records per CVE (median / mean / max)',
            lambda s: f"{np.median(s['per_cve']):.0f} / {s['per_cve'].mean():.1f} / {num(s['per_cve'].max())}"),
        row(r'Records from the 10 largest CVEs (\%)', lambda s: f"{100 * s['top10_share']:.1f}"),
        row('Snippets labelled with several CVEs', lambda s: num(s['multi_cve_code'])),
        r'\bottomrule',
        r'\end{tabular}',
        r'\end{table*}',
    ]
    return '\n'.join(lines) + '\n'


def language_stats(records):
    """Per-language counts, largest first, with rare and unidentified languages pooled as 'Other'."""
    language_of = {k: v['language'] for k, v in json.loads(LANGUAGES.read_text()).items()}
    counts = collections.Counter(language_of[r['id']] for r in records)
    shown = {name for name, c in counts.items()
             if name != 'Other' and c >= MIN_LANGUAGE_SHARE * len(records)}
    rows = collections.defaultdict(lambda: {'records': 0, 'msr': 0, 'pairs': 0, 'cves': set()})
    for r in records:
        name = language_of[r['id']]
        row = rows[name if name in shown else 'Other']
        row['records'] += 1
        row['msr'] += r['id'].startswith('msr')
        row['pairs'] += len(r['conversations']) // 2
        row['cves'].add(r['cve_id'])
    order = sorted(shown, key=lambda name: -rows[name]['records']) + ['Other']
    pooled = sorted(name for name in counts if name not in shown and name != 'Other')
    return [(name, rows[name]) for name in order], pooled, counts


def make_language_table(records):
    rows, pooled, _ = language_stats(records)
    n = len(records)
    lines = [
        r'% Requires: \usepackage{booktabs,colortbl} and the \grouprow macro of the paper preamble',
        '% Generated by make_dataset_stats.py -- do not edit by hand.',
        r'\begin{table}[t]',
        r'\centering',
        r'\small',
        r'\caption{Programming languages in the cleaned dataset. Languages are predicted from the code'
        r' by a classifier, so the counts are approximate; a C++ function that uses no C++-specific'
        r" syntax is counted as C. ``Other'' pools languages with less than "
        f'{100 * MIN_LANGUAGE_SHARE:.1f}' r'\% of the records and snippets with no confident prediction.'
        r' TS stands for TypeScript. A CVE can involve several languages.}',
        r'\label{tab:dataset-languages}',
        r'\setlength{\tabcolsep}{4pt}',
        r'\begin{tabular}{lrrrr}',
        r'\toprule',
        r'\textbf{Language} & \textbf{Records} & \textbf{\%} & \textbf{Q--A pairs} & \textbf{CVEs} \\',
        r'\midrule',
    ]
    for name, row in rows:
        if name == 'Other':
            lines.append(r'\midrule')
        lines.append(f"{name.replace('#', chr(92) + '#').replace('TypeScript', 'TS')} & {num(row['records'])} & {pct(row['records'], n)} & "
                     f"{num(row['pairs'])} & {num(len(row['cves']))} \\\\")
    lines += [
        r'\midrule',
        f"All & {num(n)} & 100.0 & {num(sum(row['pairs'] for _, row in rows))} & "
        f"{num(len({r['cve_id'] for r in records}))} \\\\",
        r'\bottomrule',
        r'\end{tabular}',
        r'\end{table}',
    ]
    return '\n'.join(lines) + '\n'


# The detailed six-sector version of this figure is kept in archive/pipeline_figure_detailed/.
PIPELINE_TEMPLATE = r'''% Requires: \usepackage{tikz} \usetikzlibrary{arrows.meta,calc}
% Generated by make_dataset_stats.py -- do not edit by hand.
% Counts come from cleaning_report.json, the language labels and the hallucination-judge summary.
\begin{figure*}[t]
\centering
\definecolor{plblue}{HTML}{DBE8FB}
\definecolor{plbluetext}{HTML}{1F3F8F}
\definecolor{plyellow}{HTML}{FCEFC4}
\definecolor{plyellowtext}{HTML}{8A4B08}
\definecolor{plgreen}{HTML}{EAF8F1}
\definecolor{plgreenline}{HTML}{6FCFAE}
\definecolor{plgreentext}{HTML}{0B5D44}
\definecolor{plpink}{HTML}{F3E8FF}
\definecolor{plpinktext}{HTML}{5B21B6}
\definecolor{plline}{HTML}{B9BFCC}
\definecolor{plred}{HTML}{B91C1C}
\definecolor{plmuted}{HTML}{4B5563}
\begin{tikzpicture}[
  font=\scriptsize,
  stage/.style={draw=#1, rounded corners=4pt, line width=0.6pt, fill=white, text width=2.95cm,
                minimum height=2.1cm, align=left, inner sep=4pt, anchor=north west,
                execute at begin node={\hyphenpenalty=10000\exhyphenpenalty=10000}},
  head/.style={rounded corners=3pt, inner xsep=4pt, inner ysep=2.5pt, anchor=south west,
               font=\footnotesize\bfseries},
  flow/.style={draw=plred, line width=1pt, -{Triangle[length=4.5pt,width=4.5pt]}},
]
\node[stage=plline] (a) at (0,0) {%
  CVEfixes + Big-Vul\\[3pt]
  {\color{plmuted}per vulnerable function:}\\
  code, CVE ID,\\ CVE description};
\node[stage=plline] (b) at (3.6,0) {%
  Llama-3.1-8B-Instruct\\
  {\color{plmuted}input: code + description}\\[3pt]
  \textbf{@GENERATED@} records\\
  \textbf{@PAIRS_IN@} Q--A pairs};
\node[stage=plline] (c) at (7.2,0) {%
  Remove minified code, unrelated snippets, non-answers, duplicates; cap @CAP@ per CVE\\[3pt]
  {\color{plmuted}$-$@DROPPED@ records}};
\node[stage=plgreenline, fill=plgreen] (d) at (10.8,0) {%
  \textbf{@RECORDS@} records\\
  \textbf{@PAIRS@} Q--A pairs\\
  @CVES@ CVEs\\
  @LANGUAGES@ languages};
\node[stage=plline] (e) at (14.4,0) {%
  @SAMPLE_RECORDS@-record sample\\
  @N_JUDGES@ LLM judges\\[3pt]
  \textbf{@MAJ@\%} of pairs hallucinated\\
  {\color{plmuted}95\% CI @MAJ_LO@--@MAJ_HI@}};
\node[head, fill=plblue, text=plbluetext] at ($(a.north west)+(0.12,-0.02)$) {1 Data Collection};
\node[head, fill=plblue, text=plbluetext] at ($(b.north west)+(0.12,-0.02)$) {2 QA Generation};
\node[head, fill=plyellow, text=plyellowtext] at ($(c.north west)+(0.12,-0.02)$) {3 Rule-based Filtering};
\node[head, fill=plgreen, text=plgreentext] at ($(d.north west)+(0.12,-0.02)$) {4 \dsname};
\node[head, fill=plpink, text=plpinktext] at ($(e.north west)+(0.12,-0.02)$) {5 Hallucination Audit};
\draw[flow] (a.east) -- (b.west);
\draw[flow] (b.east) -- (c.west);
\draw[flow] (c.east) -- (d.west);
\draw[flow, dashed] (d.east) -- (e.west);
\end{tikzpicture}
\caption{Construction of \dsname. An LLM generates question--answer conversations from each vulnerable
function and its CVE description; rule-based filters remove unusable records and pairs
(Section~\ref{sec:filtering}); a random sample of the result is audited by independent LLM judges
(Section~\ref{sec:hallucination}).}
\label{fig:pipeline}
\end{figure*}
'''


def hallucination_values():
    """Numbers for the hallucination-analysis band, from the judge summary and the sample."""
    summary = json.loads((JUDGE_DIR / 'summary.json').read_text())
    sample = json.loads((JUDGE_DIR / 'sample_records.json').read_text())
    majority = summary['hallucinated']['majority']['all']
    names = [JUDGE_NAMES.get(j, j) for j in summary['judges']]
    rates = [summary['hallucinated'][j]['all']['pairs_%'] for j in summary['judges']]
    return {
        'SAMPLE_RECORDS': len(sample), 'SAMPLE_PAIRS': sum(len(r['pairs']) for r in sample),
        'SAMPLE_CVEFIXES': sum(r['source'] == 'cvefixes' for r in sample),
        'SAMPLE_MSR': sum(r['source'] == 'msr' for r in sample),
        'N_JUDGES': ['two', 'three', 'four'][len(names) - 2],
        'JUDGE_LIST': '\\\\\n'.join(f'  \\textbullet~{n}' for n in names),
        'MAJ': f"{majority['pairs_%']:.1f}", 'MAJ_LO': f"{majority['pairs_95ci'][0]:.1f}",
        'MAJ_HI': f"{majority['pairs_95ci'][1]:.1f}",
        'JUDGE_RATES': '\\\\\n'.join(f'    {n} & {r:.1f}\\%' for n, r in zip(names, rates)),
        'FLEISS': f"{summary['fleiss_kappa']['hallucinated']:.2f}",
        'ANSWERABLE': f"{summary['answerable_from_code_%']['majority']:.0f}",
    }


def make_pipeline_figure(records):
    """Pipeline overview. Every count is read from the cleaning report, the language labels or the judge summary."""
    report = json.loads(REPORT.read_text())
    cap_key = next(k for k in report['records_dropped'] if k.startswith('over '))
    rows, _, _ = language_stats(records)
    values = {
        'GENERATED': report['input']['records'], 'PAIRS_IN': report['input']['pairs'],
        'DROPPED': report['input']['records'] - report['output']['records'],
        'RECORDS': report['output']['records'], 'PAIRS': report['output']['pairs'],
        'CVES': len({r['cve_id'] for r in records}),
        'LANGUAGES': ['one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven',
                      'twelve'][sum(name != 'Other' for name, _ in rows) - 1],
        'CAP': cap_key.split()[1],
    }
    values.update(hallucination_values())
    tex = PIPELINE_TEMPLATE
    for key, value in values.items():
        tex = tex.replace(f'@{key}@', value if isinstance(value, str) else num(value))
    assert not re.search(r'@[A-Z_]+@', tex), 'unfilled placeholder in the pipeline figure'
    return tex


def binned_share(values, edges):
    hist = np.histogram(values, bins=edges)[0]
    return [100 * h / len(values) for h in hist]


def coords(xs, ys, fmt='{:.2f}'):
    return ' '.join(f'({x},{fmt.format(y)})' for x, y in zip(xs, ys))


def make_figure(records, total):
    # (a) distinct CVEs per CVE-ID year; everything before 2010 is pooled into the 2009 bar
    years = collections.Counter(max(int(c.split('-')[1]), 2009) for c in {r['cve_id'] for r in records})
    year_xs = sorted(years)
    pre2010 = years[2009]

    # (b) snippet length in lines
    line_labels = ['1', '2--5', '6--10', '11--20', '21--50', '51--100', '101--200', '$>$200']
    line_share = binned_share(total['lines'], [1, 2, 6, 11, 21, 51, 101, 201, np.inf])

    # (c) question-answer pairs per record
    pair_labels = ['1', '2', '3', '4', '5', '6', '7', '$\\geq$8']
    pair_share = binned_share(total['pairs'], [1, 2, 3, 4, 5, 6, 7, 8, np.inf])

    # (e) question topics (keyword rules)
    topics = collections.Counter(topic_of(question_text(t))
                                 for r in records for t in r['conversations'] if t['from'] == 'human')
    n_questions = sum(topics.values())
    ordered = [k for k, _ in topics.most_common() if k != 'Other'] + ['Other']
    topic_share = [100 * topics[k] / n_questions for k in ordered]

    def sym(labels):
        return ','.join('{' + l + '}' for l in labels)

    def sym_coords(labels, ys):
        return ' '.join(f'({{{l}}},{y:.2f})' for l, y in zip(labels, ys))

    tex = rf"""% Requires: \usepackage{{pgfplots}} \usepgfplotslibrary{{groupplots}} \pgfplotsset{{compat=1.16}}
% Generated by make_dataset_stats.py -- do not edit by hand.
\begin{{figure*}}[t]
\centering
\definecolor{{dsbar}}{{HTML}}{{2A78D6}}
\definecolor{{dsgrid}}{{HTML}}{{E1E0D9}}
\definecolor{{dsaxis}}{{HTML}}{{898781}}
\pgfplotsset{{
  dsstats/.style={{
    width=0.225\textwidth, height=3.6cm,
    axis lines*=left, axis line style={{dsaxis}},
    tick style={{dsaxis}}, tick align=outside, major tick length=2pt,
    tick label style={{font=\scriptsize}},
    label style={{font=\scriptsize}},
    title style={{font=\footnotesize, yshift=-3pt}},
    ymajorgrids, grid style={{dsgrid, line width=0.3pt}},
    ymin=0, enlarge x limits=0.08,
    scaled y ticks=false,
  }},
  dslabels/.style={{
    nodes near coords, nodes near coords align={{horizontal}}, point meta=explicit symbolic,
    every node near coord/.append style={{font=\tiny, text=black, inner sep=1.5pt, anchor=west}},
  }},
}}
\begin{{tikzpicture}}
\begin{{groupplot}}[
  dsstats,
  group style={{group size=4 by 1, horizontal sep=1.4cm}},
]

% (a) distinct CVEs per year
\nextgroupplot[
  title={{(a) Distinct CVEs by year}},
  ybar, bar width=3.4pt, ylabel={{CVEs}},
  xtick={{2009,2014,2019,2024}},
  xticklabels={{$\leq$2009,2014,2019,2024}},
  enlarge x limits=0.05,
]
\addplot[fill=dsbar, draw=none] coordinates {{{coords(year_xs, [years[y] for y in year_xs], '{:d}')}}};

% (b) snippet length
\nextgroupplot[
  title={{(b) Code snippet length}},
  ybar, bar width=7pt, ylabel={{\% of records}}, xlabel={{lines}},
  symbolic x coords={{{sym(line_labels)}}}, xtick=data,
  x tick label style={{font=\tiny, rotate=60, anchor=north east, inner sep=1pt}},
]
\addplot[fill=dsbar, draw=none] coordinates {{{sym_coords(line_labels, line_share)}}};

% (c) question-answer pairs per record
\nextgroupplot[
  title={{(c) Q--A pairs per record}},
  ybar, bar width=7pt, ylabel={{\% of records}}, xlabel={{pairs}},
  symbolic x coords={{{sym(pair_labels)}}}, xtick=data,
]
\addplot[fill=dsbar, draw=none] coordinates {{{sym_coords(pair_labels, pair_share)}}};

% (d) question topics
\nextgroupplot[
  title={{(d) Question topic}}, height=4.3cm, yshift=0mm,
  y tick label style={{font=\tiny}},
  xbar, bar width=3pt, xlabel={{\% of questions}},
  xshift=12mm, width=0.25\textwidth,
  ymin={{}}, xmin=0, xmax={max(topic_share) * 1.22:.1f},
  ymajorgrids=false, xmajorgrids,
  symbolic y coords={{{sym(reversed(ordered))}}}, ytick=data,
  enlarge y limits=0.08, enlarge x limits=false,
  dslabels,
]
\addplot[fill=dsbar, draw=none] coordinates {{{' '.join(f'({s:.2f},{{{k}}}) [{s:.1f}]' for k, s in zip(ordered, topic_share))}}};

\end{{groupplot}}
\end{{tikzpicture}}
\caption{{Overview of the cleaned dataset ({num(total['records'])} records, {num(total['pairs_total'])}
question--answer pairs, {num(total['unique_cves'])} CVEs).
(a)~Distinct CVEs by the year in the CVE identifier; the first bar pools the {pre2010} CVEs from before 2010.
(b)~Length of the code snippet attached to each record.
(c)~Complete question--answer pairs per record.
(d)~Topic of each question, assigned by keyword rules.}}
\label{{fig:dataset-stats}}
\end{{figure*}}
"""
    return tex


def prose_numbers(records, stats):
    """Every number quoted in the paper text, so the prose can be checked against the data."""
    report = json.loads(REPORT.read_text())
    total = stats['All']
    n = total['records']
    out = ['Numbers quoted in the paper text. Regenerate with make_dataset_stats.py.', '']

    out.append('== Cleaning (cleaning_report.json) ==')
    out.append(f"input: {report['input']}")
    out.append(f"output: {report['output']}")
    for name, count in report['records_dropped'].items():
        out.append(f'records dropped | {name}: {count:,}')
    for name, count in report['pairs_dropped'].items():
        out.append(f'pairs dropped | {name}: {count:,}')
    kept = report['output']
    out.append(f"records kept: {pct(kept['records'], report['input']['records'])}%   "
               f"pairs kept: {pct(kept['pairs'], report['input']['pairs'])}%   "
               f"CVEs kept: {pct(kept['cves'], report['input']['cves'])}%")

    out += ['', '== Size and coverage ==']
    for _, label in SOURCES:
        s = stats[label]
        out.append(f"{label}: records {s['records']:,} ({pct(s['records'], n)}%), pairs {s['pairs_total']:,}, "
                   f"CVEs {s['unique_cves']:,}, distinct snippets {s['unique_code']:,}")
    by_source = collections.defaultdict(set)
    for r in records:
        by_source[r['cve_id']].add(r['id'].split('_')[0])
    out.append(f'CVEs in both sources: {sum(len(v) > 1 for v in by_source.values()):,}')
    years = collections.Counter(int(c.split('-')[1]) for c in by_source)
    out.append(f'CVE years: {min(years)}-{max(years)}; before 2010: {sum(v for y, v in years.items() if y < 2010)}')
    out.append('CVEs per year: ' + ', '.join(f'{y}:{years[y]}' for y in sorted(years)))

    out += ['', '== Code snippets ==']
    for _, label in SOURCES:
        s = stats[label]
        lines = s['lines']
        out.append(f"{label}: lines median {np.median(lines):.0f}, mean {lines.mean():.1f}, min {lines.min()}, "
                   f"max {lines.max():,}; single-line {pct(s['single_line'], s['records'])}%; "
                   f"<=5 lines {pct((lines <= 5).sum(), len(lines))}%; "
                   f"<=10 lines {pct((lines <= 10).sum(), len(lines))}%; "
                   f">50 lines {pct((lines > 50).sum(), len(lines))}%")

    out += ['', '== Conversations ==']
    pairs = total['pairs']
    out.append(f'pairs per record: median {np.median(pairs):.0f}, mean {pairs.mean():.2f}, '
               f'min {pairs.min()}, max {pairs.max()}; 3 to 6 pairs: {pct(((pairs >= 3) & (pairs <= 6)).sum(), n)}%')
    out.append(f"question words: median {np.median(total['q_words']):.0f}; answer words: median "
               f"{np.median(total['a_words']):.0f}, >40 words {pct((total['a_words'] > 40).sum(), len(total['a_words']))}%")
    out.append(f"conversation words: median {np.median(total['conv_words']):.0f}")

    out += ['', '== Question topics ==']
    topics = collections.Counter(topic_of(question_text(t))
                                 for r in records for t in r['conversations'] if t['from'] == 'human')
    for name, count in topics.most_common():
        out.append(f'{name}: {pct(count, sum(topics.values()))}%')

    out += ['', '== Redundancy and concentration ==']
    for _, label in SOURCES:
        s = stats[label]
        per_cve = s['per_cve']
        out.append(f"{label}: records sharing a snippet {s['shared_code']:,} ({pct(s['shared_code'], s['records'])}%); "
                   f"snippets with several CVEs {s['multi_cve_code']:,}; records per CVE median "
                   f"{np.median(per_cve):.0f}, max {per_cve.max()}; CVEs with one record "
                   f"{pct((per_cve == 1).sum(), len(per_cve))}%; top-10 CVE share {100 * s['top10_share']:.1f}%")
    out += ['', '== Programming languages (record_languages_v2.json) ==']
    rows, pooled, counts = language_stats(records)
    for name, row in rows:
        out.append(f"{name}: records {row['records']:,} ({pct(row['records'], n)}%), of which MSR {row['msr']:,}; "
                   f"pairs {row['pairs']:,}; CVEs {len(row['cves']):,}")
    out.append('pooled into Other: ' + ', '.join(f'{name} {counts[name]}' for name in pooled)
               + f"; no confident prediction {counts['Other']}")
    share = {name: row['records'] / n for name, row in rows}
    out.append(f"C + C++: {100 * (share['C'] + share['C++']):.1f}%   "
               f"PHP + JavaScript/TypeScript: {100 * (share['PHP'] + share['JavaScript/TypeScript']):.1f}%")
    per_record = {name: row['pairs'] / row['records'] for name, row in rows}
    low, high = min(per_record, key=per_record.get), max(per_record, key=per_record.get)
    out.append(f"pairs per record by language (table rows): {per_record[low]:.1f} ({low}) to "
               f"{per_record[high]:.1f} ({high})")
    return '\n'.join(out) + '\n'


def main():
    records = load_records()
    stats = {label: source_stats([r for r in records if r['id'].startswith(prefix)])
             for prefix, label in SOURCES}
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    outputs = {
        'dataset_stats_table.tex': make_table(stats),
        'dataset_stats_figure.tex': make_figure(records, stats['All']),
        'dataset_stats_languages.tex': make_language_table(records),
        'pipeline_figure.tex': make_pipeline_figure(records),
        'prose_numbers.txt': prose_numbers(records, stats),
    }
    for name, text in outputs.items():
        (OUT_DIR / name).write_text(text)
        print('wrote', OUT_DIR / name)


if __name__ == '__main__':
    main()
