"""Candidate designs for the ablation figure (LLM-as-judge score by input setting and question topic),
for the authors to choose from.

Usage:  python3 benchmark/ablation_options.py
Reads:  data/splits/cve.json (test ids; vulncodex.load_split), ablation_records.json, ablation_results.json,
        <model>/judged_cve[_<variant>].jsonl
Writes: benchmark/ablation_options/{data.json, option_<name>.tex, gallery.tex}
        (gallery.tex is a standalone document showing all options; compile it with Tectonic)

Main-text options show MAIN_TOPICS only (all questions first; the code-grounded topics last); the
appendix option shows every topic except "Other".
Records: the ablation subset, minus records missing from any setting (the same records in every setting).
Score: correct 1, partially correct 0.5; 95% intervals are bootstraps over records (2,000 draws, seed 0).
"Answered correctly" in the overlap option means labelled correct (partial answers do not count).
Setting colours are categorical slots of the dataviz reference palette (no code in neutral grey); topic
lines use an orange family for description-grounded topics and a blue family for code-grounded ones.
"""
import collections
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from vulncodex import load_split  # noqa: E402
from vulncodex.topics import topic_of  # noqa: E402

OUT = HERE / 'ablation_options'
MODEL = json.loads((HERE / 'ablation_results.json').read_text())['model']
SETTINGS = [('no_code', 'No code', '9A9893'), ('code', 'Code only', '2A78D6'),
            ('code_desc', 'Code + description', 'EB6834'), ('desc_only', 'Description only', '1BAF7A')]
SHORT = {'no_code': 'No\\\\code', 'code': 'Code\\\\only', 'code_desc': 'Code +\\\\desc.', 'desc_only': 'Desc.\\\\only'}
MAIN_TOPICS = ['All', 'Vuln. type', 'Mechanism', 'Fix', 'Location', 'Code behaviour']
CODE_TOPICS = {'Location', 'Code behaviour'}
TOPIC_COLOUR = {'All': '0B0B0B', 'Vuln. type': 'EB6834', 'Mechanism': 'C24A1C', 'Fix': 'F2A27E',
                'Location': '2A78D6', 'Code behaviour': '104281'}
LABELS = {'correct': 1.0, 'partially_correct': 0.5, 'incorrect': 0.0}
RAMP = ['F3F7FD', 'DBE9FB', 'B7D3F6', '86B6EF', '5598E7', '2A78D6', '1C5CAB', '104281']   # light -> dark
BOOTSTRAP = 2000
AXIS = r'axis line style={gray!60}, tick style={gray!60}, x tick label style={font=\footnotesize}, y tick label style={font=\footnotesize}'


def load():
    subset = set(json.loads((HERE / 'ablation_records.json').read_text())['records'])
    records = {r['id']: r for r in load_split('cve', 'test')}
    per = {}
    for s, _, _ in SETTINGS:
        path = HERE / MODEL / ('judged_cve.jsonl' if s == 'code' else f'judged_cve_{s}.jsonl')
        per[s] = {}
        for line in path.read_text().splitlines():
            v = json.loads(line)
            if v['pair_id'].split('#')[0] in subset:
                per[s][v['pair_id']] = LABELS[v['correctness']]
    keep = set.intersection(*({p.split('#')[0] for p in d} for d in per.values()))
    pairs = sorted(p for p in per['code'] if p.split('#')[0] in keep)
    topic = {}
    for p in pairs:
        rid, k = p.split('#')
        topic[p] = topic_of(records[rid]['conversations'][0::2][int(k) - 1]['value'].replace('<code_sequence>', ''))
    return per, pairs, topic, len(keep)


def tex_label(t, n, bold_all=True):
    name = 'All topics' if t == 'All' else t
    name = f'{name} ({n:,})'
    return '\\textbf{' + name + '}' if (t == 'All' and bold_all) else name


def main():
    per, pairs, topic, n_records = load()
    rng = random.Random(0)
    by_rec = collections.defaultdict(list)
    for p in pairs:
        by_rec[p.split('#')[0]].append(p)
    recs = sorted(by_rec)

    def score(s, ps):
        return 100 * sum(per[s][p] for p in ps) / len(ps)

    groups = collections.defaultdict(list)
    for p in pairs:
        groups[topic[p]].append(p)
    groups['All'] = pairs
    ci = {}
    for t in [t for t in groups if t != 'Other']:   # bootstrap over records, restricted to the topic's questions
        ci[t] = {}
        mine = {r: [p for p in by_rec[r] if t == 'All' or topic[p] == t] for r in recs}
        rs = [r for r in recs if mine[r]]
        for s, _, _ in SETTINGS:
            tot = {r: (sum(per[s][p] for p in mine[r]), len(mine[r])) for r in rs}
            boot = []
            for _ in range(BOOTSTRAP):
                draw = [tot[r] for r in rng.choices(rs, k=len(rs))]
                boot.append(100 * sum(a for a, _ in draw) / sum(b for _, b in draw))
            boot.sort()
            ci[t][s] = [round(boot[int(0.025 * BOOTSTRAP)], 1), round(boot[int(0.975 * BOOTSTRAP)], 1)]
    all_topics = [t for t in groups if t not in ('Other', 'All')]
    all_topics.sort(key=lambda t: score('code', groups[t]) - score('desc_only', groups[t]))   # code-grounded last
    all_topics = ['All'] + all_topics
    sc = {t: {s: round(score(s, groups[t]), 1) for s, _, _ in SETTINGS} for t in all_topics}
    n_q = {t: len(groups[t]) for t in all_topics}
    overlap = {}
    for t in all_topics:
        c = collections.Counter((per['code'][p] == 1, per['desc_only'][p] == 1) for p in groups[t])
        overlap[t] = {k: round(100 * v / n_q[t], 1) for k, v in
                      (('code_only', c[(True, False)]), ('both', c[(True, True)]), ('desc_only', c[(False, True)]), ('neither', c[(False, False)]))}
    data = {'model': MODEL, 'records': n_records, 'questions': len(pairs), 'main_topics': MAIN_TOPICS,
            'score': sc, 'ci95': ci, 'questions_per_topic': n_q, 'correct_overlap_%': overlap}
    OUT.mkdir(exist_ok=True)
    (OUT / 'data.json').write_text(json.dumps(data, indent=1) + '\n')

    colours = '\n'.join(f'\\definecolor{{s{i}}}{{HTML}}{{{c}}}' for i, (_, _, c) in enumerate(SETTINGS))
    colours += '\n' + '\n'.join(f'\\definecolor{{t{i}}}{{HTML}}{{{TOPIC_COLOUR[t]}}}' for i, t in enumerate(MAIN_TOPICS))
    colours += '\n' + '\n'.join(f'\\definecolor{{h{k}}}{{HTML}}{{{c}}}' for k, c in enumerate(RAMP))
    T = MAIN_TOPICS
    n = len(T)
    yticks = ','.join(str(n - j) for j in range(n))
    ylabels = ','.join('{' + tex_label(t, n_q[t]) + '}' for t in T)
    sep = f'\\addplot[gray!50, dashed, forget plot] coordinates {{(0,{n - 0.5}) (100,{n - 0.5})}};'   # under "All topics"
    caption_tail = (f'Gemma-4-31B on the same {n_records} test records ({len(pairs):,} questions) in every setting; '
                    'LLM-as-judge score, correct = 1, partially correct = 0.5.')
    options, captions = {}, {}

    # ---- A: dot plot, one row per topic, one marker per setting
    marks = ['*', 'square*', 'triangle*', 'diamond*']
    plots = '\n'.join(f'\\addplot[only marks, mark={marks[i]}, mark size=2.1pt, color=s{i}] coordinates {{'
                      + ' '.join(f'({sc[t][s]},{n - j})' for j, t in enumerate(T)) + f'}};\n\\addlegendentry{{{label}}}'
                      for i, (s, label, _) in enumerate(SETTINGS))
    rules = '\n'.join(f'\\addplot[gray!20, forget plot] coordinates {{(0,{n - j}) (100,{n - j})}};' for j in range(n))
    options['A_dot_plot'] = rf"""\begin{{tikzpicture}}
\begin{{axis}}[scale only axis, width=0.58\columnwidth, height=3.4cm, xmin=0, xmax=100, ymin=0.4, ymax={n + 0.6},
  ytick={{{yticks}}}, yticklabels={{{ylabels}}}, {AXIS}, y tick label style={{font=\scriptsize}}, ytick style={{draw=none}},
  xlabel={{\footnotesize LLM-as-judge score (\%)}},
  legend style={{font=\scriptsize, at={{(0.5,1.02)}}, anchor=south, draw=none}}, legend columns=2, legend cell align=left]
{rules}
{sep}
{plots}
\end{{axis}}
\end{{tikzpicture}}"""
    captions['A_dot_plot'] = 'LLM-as-judge score by question topic and model input. ' + caption_tail

    # ---- B: heatmap (used for main topics and, as option Z, for the appendix with every topic)
    def heatmap(rows):
        cw, ch = 1.45, 0.40
        cells = []
        for i, (s, label, _) in enumerate(SETTINGS):
            head = label.replace(' only', '\\\\only').replace(' + ', ' +\\\\')
            cells.append(f'\\node[font=\\scriptsize\\bfseries, align=center] at ({i * cw + cw / 2:.2f},{ch / 2 + 0.33:.2f}) {{{head}}};')
        for j, t in enumerate(rows):
            y = -j * ch - (0.12 if j > 0 else 0)
            cells.append(f'\\node[font=\\scriptsize, anchor=east] at (-0.08,{y:.2f}) {{{tex_label(t, n_q[t])}}};')
            for i, (s, _, _) in enumerate(SETTINGS):
                v = sc[t][s]
                k = min(len(RAMP) - 1, int(v / 100 * len(RAMP)))
                ink = 'white' if k >= 5 else 'black'
                cells.append(f'\\fill[fill=h{k}] ({i * cw + 0.03:.2f},{y - ch / 2 + 0.02:.2f}) rectangle ({(i + 1) * cw - 0.03:.2f},{y + ch / 2 - 0.02:.2f});'
                             f'\\node[font=\\scriptsize, text={ink}] at ({i * cw + cw / 2:.2f},{y:.2f}) {{{v:.0f}}};')
        return '\\begin{tikzpicture}\n' + '\n'.join(cells) + '\n\\end{tikzpicture}'
    options['B_heatmap'] = heatmap(T)
    captions['B_heatmap'] = 'LLM-as-judge score by question topic and model input. ' + caption_tail

    # ---- C: code only vs description only, dumbbells per topic
    dumb = '\n'.join(f'\\addplot[gray!50, line width=1.2pt, forget plot] coordinates {{({sc[t]["code"]},{n - j}) ({sc[t]["desc_only"]},{n - j})}};'
                     for j, t in enumerate(T))
    pc = ' '.join(f'({sc[t]["code"]},{n - j})' for j, t in enumerate(T))
    pd = ' '.join(f'({sc[t]["desc_only"]},{n - j})' for j, t in enumerate(T))
    options['C_dumbbell'] = rf"""\begin{{tikzpicture}}
\begin{{axis}}[scale only axis, width=0.55\columnwidth, height=3.4cm, xmin=0, xmax=100, ymin=0.4, ymax={n + 0.6},
  ytick={{{yticks}}}, yticklabels={{{ylabels}}}, {AXIS}, y tick label style={{font=\scriptsize}}, ytick style={{draw=none}},
  xlabel={{\footnotesize LLM-as-judge score (\%)}}, xmajorgrids, grid style={{gray!20}},
  legend style={{font=\scriptsize, at={{(0.5,1.02)}}, anchor=south, draw=none}}, legend columns=2]
{sep}
{dumb}
\addplot[only marks, mark=*, mark size=2.2pt, color=s1] coordinates {{{pc}}};
\addlegendentry{{Code only}}
\addplot[only marks, mark=diamond*, mark size=2.6pt, color=s3] coordinates {{{pd}}};
\addlegendentry{{Description only}}
\end{{axis}}
\end{{tikzpicture}}"""
    captions['C_dumbbell'] = 'LLM-as-judge score with the code only and with the CVE description only, by question topic. ' + caption_tail

    # ---- D: 100% stacked bars: correct from code only / either / description only / neither
    parts = [('code_only', 'Correct from code only', '2A78D6'), ('both', 'Correct from either', '86B6EF'),
             ('desc_only', 'Correct from description only', '1BAF7A'), ('neither', 'Correct from neither', 'D9D8D3')]
    stacks = '\n'.join(
        f'\\definecolor{{o{i}}}{{HTML}}{{{c}}}\n\\addplot[fill=o{i}, draw=white, line width=0.3pt] coordinates {{'
        + ' '.join(f'({overlap[t][k]},{n - j})' for j, t in enumerate(T)) + f'}};\n\\addlegendentry{{{label}}}'
        for i, (k, label, c) in enumerate(parts))
    options['D_overlap'] = rf"""\begin{{tikzpicture}}
\begin{{axis}}[xbar stacked, bar width=8pt, scale only axis, width=0.55\columnwidth, height=3.4cm, xmin=0, xmax=100,
  ymin=0.4, ymax={n + 0.6}, ytick={{{yticks}}}, yticklabels={{{ylabels}}}, {AXIS}, y tick label style={{font=\scriptsize}},
  ytick style={{draw=none}}, xlabel={{\footnotesize Share of questions (\%)}},
  legend style={{font=\scriptsize, at={{(0.5,1.02)}}, anchor=south, draw=none}}, legend columns=2, legend cell align=left]
{stacks}
\end{{axis}}
\end{{tikzpicture}}"""
    captions['D_overlap'] = ('For each question, whether Gemma-4-31B answers it correctly with the code only, with the CVE '
                             f'description only, with either, or with neither ({n_records} test records, LLM-as-judge).')

    # ---- E: slope chart, settings on x, one line per topic
    xt = ','.join('{' + SHORT[s] + '}' for s, _, _ in SETTINGS)
    lines = []
    for i, t in enumerate(T):
        style = 'dashed, line width=1.1pt' if t == 'All' else 'line width=1.0pt'
        mark = 'square*' if t in CODE_TOPICS else ('*' if t != 'All' else 'none')
        lines.append(f'\\addplot[color=t{i}, {style}, mark={mark}, mark size=1.6pt] coordinates {{'
                     + ' '.join(f'({k},{sc[t][s]})' for k, (s, _, _) in enumerate(SETTINGS)) + '};\n'
                     f'\\addlegendentry{{{"All topics" if t == "All" else t}}}')
    options['E_slope'] = rf"""\begin{{tikzpicture}}
\begin{{axis}}[scale only axis, width=0.55\columnwidth, height=3.8cm, xmin=-0.2, xmax=3.2, ymin=0, ymax=100,
  xtick={{0,1,2,3}}, xticklabels={{{xt}}}, {AXIS}, x tick label style={{font=\scriptsize, align=center}},
  ylabel={{\footnotesize LLM-as-judge score (\%)}}, ymajorgrids, grid style={{gray!20}},
  legend style={{font=\scriptsize, at={{(1.03,0.5)}}, anchor=west, draw=none}}, legend cell align=left]
{chr(10).join(lines)}
\end{{axis}}
\end{{tikzpicture}}"""
    captions['E_slope'] = ('LLM-as-judge score of each question topic across the four inputs; orange: topics answered from the '
                           'CVE description, blue: topics answered from the code. ' + caption_tail)

    # ---- F: small multiples, one bar panel per topic
    panels = []
    for j, t in enumerate(T):
        bars = '\n'.join(f'\\addplot[fill=s{i}, draw=none, bar shift=0pt] coordinates {{({i},{sc[t][s]})}};'
                         for i, (s, _, _) in enumerate(SETTINGS))
        ylab = 'yticklabels={}, ' if j % 3 else ''
        name = '\\textbf{All topics}' if t == 'All' else t
        title = f'{name}\\\\({n_q[t]:,})'
        panels.append(f'\\nextgroupplot[title={{{title}}}, title style={{align=center}}, {ylab}]\n{bars}')
    legend = ' '.join(f'\\addlegendimage{{area legend, fill=s{i}, draw=none}}\\addlegendentry{{{label}}}'
                      for i, (_, label, _) in enumerate(SETTINGS))
    options['F_small_multiples'] = rf"""\begin{{tikzpicture}}
\begin{{groupplot}}[group style={{group size=3 by 2, horizontal sep=16pt, vertical sep=34pt}},
  scale only axis, width=0.24\columnwidth, height=1.6cm, ybar, /pgf/bar width=7pt, ymin=0, ymax=100, xmin=-0.6, xmax=3.6,
  xtick=\empty, ytick={{0,50,100}}, {AXIS}, title style={{font=\scriptsize, yshift=-3pt}}, ymajorgrids, grid style={{gray!20}}]
{chr(10).join(panels)}
\end{{groupplot}}
\begin{{axis}}[hide axis, scale only axis, width=1pt, height=1pt, at={{(group c2r2.south)}}, anchor=north, yshift=-6pt,
  xmin=0, xmax=1, ymin=0, ymax=1, legend style={{font=\scriptsize, draw=none, at={{(0.5,0)}}, anchor=north}}, legend columns=2,
  legend cell align=left]
{legend}
\end{{axis}}
\end{{tikzpicture}}"""
    captions['F_small_multiples'] = 'LLM-as-judge score by model input, one panel per question topic. ' + caption_tail

    # ---- G: grouped horizontal bars
    gbars = '\n'.join(f'\\addplot[fill=s{i}, draw=none] coordinates {{' + ' '.join(f'({sc[t][s]},{n - j})' for j, t in enumerate(T))
                      + f'}};\n\\addlegendentry{{{label}}}' for i, (s, label, _) in reversed(list(enumerate(SETTINGS))))
    options['G_grouped_bars'] = rf"""\begin{{tikzpicture}}
\begin{{axis}}[xbar=0pt, bar width=3.2pt, scale only axis, width=0.55\columnwidth, height=4.6cm, xmin=0, xmax=100,
  ymin=0.4, ymax={n + 0.6}, ytick={{{yticks}}}, yticklabels={{{ylabels}}}, {AXIS}, y tick label style={{font=\scriptsize}},
  ytick style={{draw=none}}, xlabel={{\footnotesize LLM-as-judge score (\%)}}, xmajorgrids, grid style={{gray!20}},
  legend style={{font=\scriptsize, at={{(0.5,1.02)}}, anchor=south, draw=none}}, legend columns=2, legend cell align=left,
  reverse legend, area legend]
{gbars}
\end{{axis}}
\end{{tikzpicture}}"""
    captions['G_grouped_bars'] = 'LLM-as-judge score by question topic and model input. ' + caption_tail

    # ---- H: diverging bars: what the code adds, in points
    d1 = ' '.join(f'({sc[t]["code"] - sc[t]["desc_only"]:.1f},{n - j})' for j, t in enumerate(T))
    d2 = ' '.join(f'({sc[t]["code_desc"] - sc[t]["desc_only"]:.1f},{n - j})' for j, t in enumerate(T))
    options['H_diverging'] = rf"""\begin{{tikzpicture}}
\begin{{axis}}[xbar=0pt, bar width=5pt, scale only axis, width=0.55\columnwidth, height=3.6cm, xmin=-75, xmax=40,
  ymin=0.4, ymax={n + 0.6}, ytick={{{yticks}}}, yticklabels={{{ylabels}}}, {AXIS}, y tick label style={{font=\scriptsize}},
  ytick style={{draw=none}}, xlabel={{\footnotesize Difference in LLM-as-judge score (points)}}, xmajorgrids, grid style={{gray!20}},
  legend style={{font=\scriptsize, at={{(0.5,1.02)}}, anchor=south, draw=none}}, legend columns=1, legend cell align=left,
  reverse legend, area legend]
\addplot[black!60, forget plot] coordinates {{(0,0.4) (0,{n + 0.6})}};
\addplot[fill=s2, draw=none] coordinates {{{d2}}};
\addlegendentry{{Code + description minus description only}}
\addplot[fill=s1, draw=none] coordinates {{{d1}}};
\addlegendentry{{Code only minus description only}}
\end{{axis}}
\end{{tikzpicture}}"""
    captions['H_diverging'] = ('What the code contributes, by question topic. Blue: code only minus description only (right of zero: '
                               'the code alone answers better than the description alone). Orange: code and description minus '
                               'description only (what adding the code to the description gains). ' + caption_tail)

    # ---- Z: appendix, every topic
    options['Z_appendix_all_topics'] = heatmap(all_topics)
    captions['Z_appendix_all_topics'] = ('Appendix version: LLM-as-judge score for every question topic and model input; '
                                         'topics ordered by how much better the description alone does than the code alone. ' + caption_tail)

    for old in OUT.glob('option_*.tex'):
        old.unlink()
    for name, body in options.items():
        (OUT / f'option_{name}.tex').write_text(
            f'% Generated by benchmark/ablation_options.py -- do not edit by hand.\n{colours}\n{body}\n')
    gallery = r"""\documentclass[10pt]{article}
\usepackage[margin=1.5cm]{geometry}
\usepackage{pgfplots}\pgfplotsset{compat=1.18}\usepgfplotslibrary{groupplots}
\usepackage{xcolor}
\setlength{\parindent}{0pt}
\begin{document}
""" + '\n\\vspace{1em}\n'.join(
        f'\\begin{{minipage}}{{\\textwidth}}\\textbf{{Option {name[0]}: {name[2:].replace("_", " ")}}}\\par\\smallskip\n'
        f'\\centering\\begin{{minipage}}{{0.75\\textwidth}}\\centering\\setlength{{\\columnwidth}}{{8.6cm}}\\input{{option_{name}.tex}}\\end{{minipage}}\\par\\smallskip\n'
        f'\\raggedright\\small {captions[name]}\\par\\medskip\\hrule\\end{{minipage}}'
        for name in options) + '\n\\end{document}\n'
    (OUT / 'gallery.tex').write_text(gallery)
    print(json.dumps({t: sc[t] for t in T}, indent=1))


if __name__ == '__main__':
    main()
