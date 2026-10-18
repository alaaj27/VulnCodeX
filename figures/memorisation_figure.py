"""Four candidate designs for Figure 4 (judge score on old vs recent CVEs), for the authors to choose from.

Usage:  python figures/memorisation_figure.py
Reads:  data/splits/cve.json (test ids; vulncodex.load_split), <model>/judged_cve.json for the four main models
Writes: figures/out/memorisation_options/{data.json, option_<name>.tex, gallery.tex}
        figures/out/memorisation_figure.tex  (option 3, paired bars: the design chosen for the paper;
        figures/export_figures.py turns it into figures/out/fig_memorisation.pdf)
        (gallery.tex is a standalone document showing all four options; compile it with Tectonic)

All four use CVEfixes test records only (Big-Vul ends in 2019 and scores higher, which would confound
year with source), five CVE-year bins, and 95% bootstrap intervals over records (2,000 draws, seed 0).
Model colours are categorical slots 1-4 of the dataviz reference palette, in fixed order; the heatmap
uses a single-hue blue ramp from the same palette.
"""
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from vulncodex import load_split  # noqa: E402
B = ROOT / 'benchmark'
OUT = HERE / 'out' / 'memorisation_options'
MODELS = [('foundation-sec-8b-instruct', 'Foundation-Sec-8B', '2A78D6'), ('qwen2.5-coder-7b-instruct', 'Qwen2.5-Coder-7B', 'EB6834'),
          ('opencoder-8b-instruct', 'OpenCoder-8B', '1BAF7A'), ('gemma-4-31b-it', 'Gemma-4-31B', 'EDA100')]
BINS = [('$\\leq$2015', 0, 2015), ('2016--17', 2016, 2017), ('2018--19', 2018, 2019), ('2020--21', 2020, 2021), ('2022--24', 2022, 2024)]
RAMP = ['DBE9FB', 'B7D3F6', '86B6EF', '5598E7', '2A78D6', '1C5CAB', '104281']   # light -> dark
LABELS = {'correct': 1.0, 'partially_correct': 0.5, 'incorrect': 0.0}
BOOTSTRAP = 2000


def mean(recs):
    return 100 * sum(s for r in recs for s in r) / sum(len(r) for r in recs)


def ci(recs, rng):
    boot = sorted(mean(rng.choices(recs, k=len(recs))) for _ in range(BOOTSTRAP))
    return boot[int(0.025 * BOOTSTRAP)], boot[int(0.975 * BOOTSTRAP)]


def colours():
    return '\n'.join(f'\\definecolor{{m{i}}}{{HTML}}{{{c}}}' for i, (_, _, c) in enumerate(MODELS))


def main():
    OUT.mkdir(exist_ok=True)
    records = load_split('cve', 'test')
    year = {r['id']: int(r['cve_id'].split('-')[1]) for r in records if r['id'].startswith('cvefixes')}
    rng = random.Random(0)
    data = {}
    for key, name, _ in MODELS:
        per = {}
        for line in (B / key / 'judged_cve.jsonl').read_text().splitlines():
            v = json.loads(line)
            rid = v['pair_id'].split('#')[0]
            if rid in year:
                per.setdefault(rid, []).append(LABELS[v['correctness']])
        data[name] = []
        for label, lo, hi in BINS:
            recs = [s for rid, s in per.items() if lo <= year[rid] <= hi]
            a, b = ci(recs, rng)
            data[name].append({'bin': label, 'records': len(recs), 'score': round(mean(recs), 1), 'ci': [round(a, 1), round(b, 1)]})
    (OUT / 'data.json').write_text(json.dumps(data, indent=1) + '\n')
    names = [n for _, n, _ in MODELS]
    n_old, n_new = data[names[0]][0]['records'], data[names[0]][-1]['records']

    # ---- (1) dumbbell: old (filled) -> recent (open), per model
    rows = []
    for i, n in enumerate(names):
        y = len(names) - i
        o, r = data[n][0], data[n][-1]
        rows.append(rf"\draw[m{i}, line width=1.4pt] (axis cs:{r['score']},{y}) -- (axis cs:{o['score']},{y});")
        rows.append(rf"\addplot[only marks, mark=*, mark size=2.6pt, m{i}, error bars/.cd, x dir=both, x explicit, error bar style={{line width=0.6pt}}] coordinates {{({o['score']},{y + 0.12}) -= ({o['score'] - o['ci'][0]:.1f},0) += ({o['ci'][1] - o['score']:.1f},0)}};")
        rows.append(rf"\addplot[only marks, mark=*, mark size=2.6pt, m{i}, mark options={{fill=white, line width=1pt}}, error bars/.cd, x dir=both, x explicit, error bar style={{line width=0.6pt}}] coordinates {{({r['score']},{y - 0.12}) -= ({r['score'] - r['ci'][0]:.1f},0) += ({r['ci'][1] - r['score']:.1f},0)}};")
    dumbbell = rf"""\begin{{tikzpicture}}
\begin{{axis}}[scale only axis, width=0.62\columnwidth, height=3.3cm, xmin=20, xmax=52, ymin=0.4, ymax={len(names) + 0.6},
  ytick={{{','.join(str(len(names) - i) for i in range(len(names)))}}}, yticklabels={{{','.join(names)}}},
  tick label style={{font=\footnotesize}}, xlabel={{\footnotesize Judge score (\%)}}, xmajorgrids, grid style={{gray!20}},
  axis line style={{gray!60}}, tick style={{gray!60}}, clip=false]
{chr(10).join(rows)}
\node[font=\scriptsize, anchor=south west] at (rel axis cs:0,1.02) {{$\bullet$ old ($\leq$2015, {n_old} records)\quad $\circ$ recent (2022--24, {n_new} records)}};
\end{{axis}}
\end{{tikzpicture}}"""

    # ---- (2) lines over five year bins with CI bands
    lines = []
    for i, n in enumerate(names):
        pts = ' '.join(f"({k},{d['score']})" for k, d in enumerate(data[n]))
        up = ' '.join(f"({k},{d['ci'][1]})" for k, d in enumerate(data[n]))
        lo = ' '.join(f"({k},{d['ci'][0]})" for k, d in reversed(list(enumerate(data[n]))))
        lines.append(rf"\addplot[fill=m{i}, fill opacity=0.12, draw=none, forget plot] coordinates {{{up} {lo}}} --cycle;")
        lines.append(rf"\addplot[m{i}, line width=1.2pt, mark=*, mark size=1.6pt] coordinates {{{pts}}};")
        lines.append(rf"\addlegendentry{{{n}}}")
    lineplot = rf"""\begin{{tikzpicture}}
\begin{{axis}}[scale only axis, width=0.82\columnwidth, height=3.6cm, xmin=-0.2, xmax={len(BINS) - 0.8}, ymin=18, ymax=55,
  xtick={{{','.join(str(k) for k in range(len(BINS)))}}}, xticklabels={{{','.join(b[0] for b in BINS)}}},
  tick label style={{font=\footnotesize}}, ylabel={{\footnotesize Judge score (\%)}}, xlabel={{\footnotesize CVE year}},
  ymajorgrids, grid style={{gray!20}}, axis line style={{gray!60}}, tick style={{gray!60}},
  legend style={{font=\scriptsize, at={{(0.5,1.03)}}, anchor=south, draw=none}}, legend columns=2]
{chr(10).join(lines)}
\end{{axis}}
\end{{tikzpicture}}"""

    # ---- (3) paired bars: old vs recent per model
    olds = ' '.join(f"({i},{data[n][0]['score']}) +- (0,0) " for i, n in enumerate(names))
    bars_rows = []
    for legend, idx, style in (('Old ($\\leq$2015)', 0, 'fill=gray!65'), ('Recent (2022--24)', -1, 'fill=gray!25')):
        coords = ' '.join(f"({i},{data[n][idx]['score']}) -= (0,{data[n][idx]['score'] - data[n][idx]['ci'][0]:.1f}) += (0,{data[n][idx]['ci'][1] - data[n][idx]['score']:.1f})"
                          for i, n in enumerate(names))
        bars_rows.append(rf"\addplot[{style}, draw=none, error bars/.cd, y dir=both, y explicit, error bar style={{line width=0.6pt, black!70}}] coordinates {{{coords}}};")
        bars_rows.append(r"\addlegendentry{" + legend + "}")
    bars = rf"""\begin{{tikzpicture}}
\begin{{axis}}[scale only axis, width=0.82\columnwidth, height=3.4cm, ybar=2pt, bar width=18pt, ymin=0, ymax=55,
  xtick={{{','.join(str(i) for i in range(len(names)))}}}, xticklabels={{{','.join(names)}}}, enlarge x limits=0.15,
  x tick label style={{font=\scriptsize}}, y tick label style={{font=\footnotesize}}, ylabel={{\footnotesize Judge score (\%)}},
  ymajorgrids, grid style={{gray!20}}, axis line style={{gray!60}}, tick style={{gray!60}},
  legend style={{font=\scriptsize, at={{(0.5,1.03)}}, anchor=south, draw=none}}, legend columns=2]
{chr(10).join(bars_rows)}
\end{{axis}}
\end{{tikzpicture}}"""

    # ---- (4) heatmap: models x year bins, single-hue ramp, value in every cell
    allv = [d['score'] for n in names for d in data[n]]
    lo_v, hi_v = min(allv), max(allv)
    cells = []
    for i, n in enumerate(names):
        for k, d in enumerate(data[n]):
            step = round((d['score'] - lo_v) / (hi_v - lo_v) * (len(RAMP) - 1))
            ink = 'white' if step >= 4 else 'black'
            cells.append(rf"\fill[hm{step}] ({k * 1.25},{-i * 0.55}) rectangle ++(1.21,-0.51); "
                         rf"\node[font=\scriptsize, text={ink}] at ({k * 1.25 + 0.605},{-i * 0.55 - 0.255}) {{{d['score']:.1f}}};")
        cells.append(rf"\node[font=\footnotesize, anchor=east] at (-0.08,{-i * 0.55 - 0.255}) {{{n}}};")
    for k, b in enumerate(BINS):
        cells.append(rf"\node[font=\footnotesize] at ({k * 1.25 + 0.605},0.25) {{{b[0]}}};")
    heat = '\\begin{tikzpicture}\n' + '\n'.join(f'\\definecolor{{hm{s}}}{{HTML}}{{{c}}}' for s, c in enumerate(RAMP)) + '\n' + '\n'.join(cells) + '\n\\end{tikzpicture}'

    for name, body in (('dumbbell', dumbbell), ('lines', lineplot), ('bars', bars), ('heatmap', heat)):
        (OUT / f'option_{name}.tex').write_text(f'% Generated by fig4_options.py\n{colours()}\n{body}\n')
    gallery = r"""\documentclass[10pt]{article}
\usepackage[margin=0.5in]{geometry}
\usepackage{mathptmx}
\usepackage{pgfplots}\pgfplotsset{compat=1.16}
\setlength{\columnwidth}{3.5in}
\pagestyle{empty}
\begin{document}
""" + '\n\n'.join(rf"""\noindent\textbf{{Option {i}: {title}}}\par\medskip
\input{{option_{name}.tex}}\par\vspace{{1.2em}}""" for i, (name, title) in enumerate(
        [('dumbbell', 'dumbbell (old $\\bullet$ to recent $\\circ$)'), ('lines', 'score by CVE year, 95\\% bands'),
         ('bars', 'paired bars with 95\\% intervals'), ('heatmap', 'heatmap, models $\\times$ CVE year')], 1)) + '\n\\end{document}\n'
    (OUT / 'gallery.tex').write_text(gallery)
    # The design the authors chose (option 3, paired bars) becomes the paper's Figure 4.
    # In the paper's single column the model names collide, so they are broken over two lines.
    paper_bars = (bars.replace('width=0.82\\columnwidth', 'width=0.80\\columnwidth')
                  .replace('xticklabels={' + ','.join(names) + '}',
                           'xticklabels={{Foundation-\\\\Sec-8B},{Qwen2.5-\\\\Coder-7B},{OpenCoder-\\\\8B},{Gemma-4-\\\\31B}}')
                  .replace('x tick label style={font=\\scriptsize}', 'x tick label style={font=\\scriptsize, align=center}')
                  .replace('Judge score (\\%)', 'LLM-as-judge score (\\%)')
                  .replace('legend columns=2]', 'legend columns=2, area legend]'))
    fig = r"""% Generated by figures/memorisation_figure.py (option 3, the design used in the paper) -- do not edit by hand.
\begin{figure}[t]
\centering
""" + paper_bars + rf"""
\caption{{Judge score on old ($\leq$2015, {n_old} records) and recent (2022--2024, {n_new} records) CVEs, CVEfixes test
records only. Error bars are 95\% bootstrap intervals over records. Scores in the intermediate years fluctuate
(Section~\ref{{sec:benchmark-results}}).}}
\label{{fig:memorisation}}
\end{{figure}}
"""
    (ROOT / 'figures' / 'out' / 'memorisation_figure.tex').write_text(fig)
    for n in names:
        print(n, [(d['bin'], d['records'], d['score'], d['ci']) for d in data[n]])


if __name__ == '__main__':
    main()
