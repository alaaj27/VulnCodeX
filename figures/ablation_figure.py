"""Two-panel ablation figure in a journal (Nature-like) style.

Usage:  python figures/ablation_figure.py
Reads:  benchmark/ablation_options/data.json   (written by ablation_options.py)
Writes: figures/out/fig_ablation.pdf                              (the figure; generated -- do not edit by hand)
        figures/out/ablation_figure.png                  (preview)
        figures/out/ablation_figure.tex                  (a float with a caption drafted from the data; the
                                                           manuscript holds its own caption)
(The earlier two-panel version with one line per topic is in archive/ablation_figure_all_lines/.)

(a) LLM-as-judge score per model input, all questions; (b) the same by topic. The topics that the CVE description answers far better than the code
(DESC_TOPICS) are drawn as one orange band: the band spans their range and the line is their pooled score
(all their questions together). Location and code behaviour (blue) and severity (grey) are drawn
individually with 95% bootstrap intervals over records; the dashed line is all questions. Per-topic numbers
for every topic are in the appendix heatmap (ablation_options.py, option Z).
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import font_manager

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA = json.loads((ROOT / 'benchmark' / 'ablation_options' / 'data.json').read_text())
OUT = ROOT / 'figures' / 'out'

SETTINGS = ['no_code', 'code', 'code_desc', 'desc_only']
XSHORT = ['No\ncode', 'Code\nonly', 'Code +\ndesc.', 'Desc.\nonly']
XLABELS = ['No code', 'Code\nonly', 'Code +\ndescription', 'Description\nonly']
DESC_TOPICS = ['Vuln. type', 'Mechanism', 'Fix', 'Impact', 'Exploitation', 'Affected software']
LINES = [('Code behaviour', '#104281', 1.5), ('Location', '#2a78d6', 1.5), ('Severity', '#8a8780', 1.0)]
ORANGE, BLUE = '#e46430', '#2a78d6'
INK, MUTED, GRID = '#1a1a1a', '#5f5e5a', '#e4e3de'
SETTING_COLOUR = {'no_code': '#9a9893', 'code': BLUE, 'code_desc': '#4a4a4a', 'desc_only': ORANGE}


def setup_font():
    for f in font_manager.findSystemFonts():
        if 'LiberationSans-' in f:
            font_manager.fontManager.addfont(f)
    plt.rcParams.update({
        'font.family': 'Liberation Sans', 'font.size': 7, 'axes.labelsize': 7,
        'xtick.labelsize': 6.5, 'ytick.labelsize': 6.5, 'axes.edgecolor': MUTED, 'axes.linewidth': 0.6,
        'xtick.color': MUTED, 'ytick.color': MUTED, 'xtick.major.width': 0.6, 'ytick.major.width': 0.6,
        'xtick.major.size': 2.5, 'ytick.major.size': 2.5, 'axes.labelcolor': INK, 'text.color': INK,
        'axes.spines.top': False, 'axes.spines.right': False, 'pdf.fonttype': 42})


def panel_label(ax, letter, title):
    ax.text(-0.02, 1.06, letter, transform=ax.transAxes, fontsize=9, fontweight='bold', va='bottom', ha='right')
    ax.text(0.0, 1.06, title, transform=ax.transAxes, fontsize=7.5, va='bottom', ha='left', color=INK)


def main():
    setup_font()
    sc, ci, n_q = DATA['score'], DATA['ci95'], DATA['questions_per_topic']
    n_desc = sum(n_q[t] for t in DESC_TOPICS)
    pooled = [sum(sc[t][s] * n_q[t] for t in DESC_TOPICS) / n_desc for s in SETTINGS]
    lo = [min(sc[t][s] for t in DESC_TOPICS) for s in SETTINGS]
    hi = [max(sc[t][s] for t in DESC_TOPICS) for s in SETTINGS]

    fig = plt.figure(figsize=(7.16, 2.6))
    gs = fig.add_gridspec(1, 2, width_ratios=[0.62, 2.0], wspace=0.2, left=0.06, right=0.84, bottom=0.17, top=0.88)
    x = range(4)

    # ---- (a) all questions, per input
    ax = fig.add_subplot(gs[0])
    for k, s in enumerate(SETTINGS):
        v, (a, b) = sc['All'][s], ci['All'][s]
        ax.vlines(k, a, b, color=SETTING_COLOUR[s], lw=1.6)
        ax.plot(k, v, 'o', ms=5, color=SETTING_COLOUR[s], mec='white', mew=0.6, zorder=3)
        ax.text(k + 0.17, v, f'{v:.0f}', va='center', ha='left', fontsize=6.5, color=SETTING_COLOUR[s])
    ax.axvspan(0.6, 1.4, color=BLUE, alpha=0.07, lw=0)
    ax.text(1, 1.5, 'benchmark\ntask', ha='center', va='bottom', fontsize=5.5, color=BLUE, linespacing=0.9)
    ax.set_xlim(-0.5, 3.6)
    ax.set_ylim(0, 102)
    ax.set_xticks(list(x), XSHORT, fontsize=5.8)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_ylabel('LLM-as-judge score (%)')
    ax.yaxis.grid(True, color=GRID, lw=0.5)
    ax.set_axisbelow(True)
    panel_label(ax, 'a', 'All questions')

    # ---- (b) by topic group
    ax = fig.add_subplot(gs[1], sharey=fig.axes[0])
    ax.tick_params(axis='y', labelleft=False)
    panel_label(ax, 'b', 'By question topic')
    ax.axvspan(0.8, 1.2, color=BLUE, alpha=0.07, lw=0)
    for y in (25, 50, 75, 100):
        ax.plot([-0.15, 3.0], [y, y], color=GRID, lw=0.5, zorder=0)

    ax.fill_between(x, lo, hi, color=ORANGE, alpha=0.18, lw=0, zorder=1)
    ax.plot(x, pooled, color=ORANGE, lw=1.5, zorder=3, solid_capstyle='round')
    ax.plot(x, pooled, 'o', ms=3.2, color=ORANGE, mec='white', mew=0.5, zorder=4)
    for name, colour, lw in LINES:
        ys = [sc[name][s] for s in SETTINGS]
        ax.plot(x, ys, color=colour, lw=lw, zorder=3, solid_capstyle='round')
        for k, s in enumerate(SETTINGS):
            ax.vlines(k, *ci[name][s], color=colour, lw=0.6, alpha=0.75, zorder=2)
        ax.plot(x, ys, 'o', ms=3.2, color=colour, mec='white', mew=0.5, zorder=4)
    ax.plot(x, [sc['All'][s] for s in SETTINGS], ls=(0, (3, 2)), color=INK, lw=1.1, zorder=5)

    # end labels; positions nudged by hand only where two end points are within a few points of each other
    labels = [(pooled[3], 'Description topics', f'{n_desc:,} questions', ORANGE, True),
              (sc['All']['desc_only'], 'All questions', f'{n_q["All"]:,}', INK, False),
              (sc['Code behaviour']['desc_only'], 'Code behaviour', f'{n_q["Code behaviour"]:,} questions', '#104281', True),
              (sc['Severity']['desc_only'] + 3.5, 'Severity', f'{n_q["Severity"]:,}', '#8a8780', False),
              (sc['Location']['desc_only'] - 1.5, 'Location', f'{n_q["Location"]:,}', BLUE, True)]
    for y, name, count, colour, bold in labels:
        ax.text(3.1, y, name, va='center', ha='left', fontsize=6.3, color=colour, clip_on=False,
                fontweight='bold' if bold else 'normal')
        ax.text(3.1, y - 4.4, count, va='center', ha='left', fontsize=5.3, color=MUTED, clip_on=False)

    drop = sc['Location']['code_desc'] - sc['Location']['desc_only']
    ax.annotate('', xy=(2.93, sc['Location']['desc_only'] - 4), xytext=(2.07, sc['Location']['code_desc'] - 4),
                arrowprops=dict(arrowstyle='-|>', color=BLUE, lw=0.6, shrinkA=2, shrinkB=2, mutation_scale=6))
    ax.text(2.1, 46, f'−{drop:.0f} pts\nwithout code', fontsize=5.6, color=BLUE, ha='left', va='top', linespacing=0.95)

    ax.set_xlim(-0.15, 3.0)
    ax.spines['bottom'].set_bounds(0, 3)
    ax.set_ylim(0, 102)
    ax.set_xticks(list(x), XLABELS, fontsize=6.2)
    fig.savefig(ROOT / 'figures' / 'out' / 'fig_ablation.pdf')
    fig.savefig(OUT / 'ablation_figure.png', dpi=300)

    n_rec, n_qs = DATA['records'], DATA['questions']
    (OUT / 'ablation_figure.tex').write_text(rf"""% Generated by figures/ablation_figure.py -- do not edit by hand.
\begin{{figure*}}[t]
\centering
\includegraphics[width=\textwidth]{{fig_ablation.pdf}}
\caption{{LLM-as-judge score of Gemma-4-31B on the same {n_rec} test records ({n_qs:,} questions) with four inputs;
the shaded column is the benchmark task. (a)~All questions. (b)~By question topic. Orange: the six topics that the CVE description answers far better than
the code (vulnerability type, mechanism, fix, impact, exploitation and affected software), pooled (line) and their
range (band). Blue: the topics that need the code; removing the code from the
input lowers their scores by {drop:.0f} (location) and
{sc['Code behaviour']['code_desc'] - sc['Code behaviour']['desc_only']:.0f} (code behaviour) points. Grey: severity,
which neither input answers well. Dashed: all questions. Vertical bars are 95\% bootstrap intervals over records;
Table~\ref{{tab:ablation-topics}} in the appendix gives every topic.}}
\label{{fig:ablation}}
\end{{figure*}}
""")


if __name__ == '__main__':
    main()
