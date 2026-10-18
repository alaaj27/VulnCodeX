"""Figure: LLM-as-judge score of Qwen2.5-Coder-7B before and after fine-tuning on VulnCodeX, by question topic.

Usage:  python figures/finetune_figure.py
Reads:  finetune/comparison_cve.json   (compare.py)
Writes: figures/out/fig_finetune.pdf (column width; generated -- do not edit by hand)

One row per topic: open circle = zero-shot, filled circle = fine-tuned, joined by a line. Colours follow
the ablation figure: orange = description topics, blue = topics that need the code, grey = severity
(left out of training) and all questions (black). The number on the right is the paired difference; it
is bold when its 95% bootstrap interval excludes zero. "Other" (questions outside the topic rules) is
counted in "All questions" only.
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import font_manager

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA = json.loads((ROOT / 'finetune' / 'comparison_cve.json').read_text())
OUT = ROOT / 'figures' / 'out' / 'fig_finetune.pdf'

DESC = ['Exploitation', 'Impact', 'Vuln. type', 'Mechanism', 'Fix', 'Affected software']
CODE = ['Location', 'Code behaviour']
ORANGE, BLUE, GREY, INK, MUTED, GRID = '#e46430', '#2a78d6', '#8a8780', '#1a1a1a', '#5f5e5a', '#e4e3de'


def setup_font():
    for f in font_manager.findSystemFonts():
        if 'LiberationSans-' in f:
            font_manager.fontManager.addfont(f)
    plt.rcParams.update({
        'font.family': 'Liberation Sans', 'font.size': 7, 'xtick.labelsize': 6.5, 'ytick.labelsize': 6.5,
        'axes.edgecolor': MUTED, 'axes.linewidth': 0.6, 'xtick.color': MUTED, 'ytick.color': MUTED,
        'xtick.major.width': 0.6, 'xtick.major.size': 2.5, 'axes.labelcolor': INK, 'text.color': INK,
        'axes.spines.top': False, 'axes.spines.right': False, 'axes.spines.left': False, 'pdf.fonttype': 42})


def main():
    setup_font()
    topics = DATA['by_topic']
    rows = [('All questions', DATA['all'], INK)]
    rows += [(t, topics[t], ORANGE) for t in sorted(DESC, key=lambda t: -topics[t]['difference'])]
    rows += [(t, topics[t], BLUE) for t in CODE]
    rows += [('Severity', topics['Severity'], GREY)]
    fig, ax = plt.subplots(figsize=(3.45, 2.75))
    fig.subplots_adjust(left=0.30, right=0.86, bottom=0.14, top=0.90)
    n = len(rows)
    for i, (name, v, colour) in enumerate(rows):
        y = n - 1 - i - (0 if i == 0 else 0.4)          # a small gap under "All questions"
        a, b = v['zero_shot'], v['fine_tuned']
        ax.plot([a, b], [y, y], color=colour, lw=1.6, alpha=0.55, solid_capstyle='round', zorder=1)
        ax.plot(a, y, 'o', ms=4, mfc='white', mec=colour, mew=1.0, zorder=2)
        ax.plot(b, y, 'o', ms=4, color=colour, zorder=3)
        lo, hi = v['difference_95ci']
        significant = lo > 0 or hi < 0
        ax.text(1.02, y, f"{v['difference']:+.1f}".replace('-', '\u2212'), transform=ax.get_yaxis_transform(), va='center', ha='left',
                fontsize=6.5, color=colour, fontweight='bold' if significant else 'normal')
        label = name + (' (not trained)' if name == 'Severity' else '')
        ax.text(-0.02, y, label, transform=ax.get_yaxis_transform(), va='center', ha='right', fontsize=6.5,
                color=INK if i == 0 else MUTED, fontweight='bold' if i == 0 else 'normal')
    ax.set_yticks([])
    ax.set_xlim(15, 100)
    ax.set_xticks([20, 40, 60, 80, 100])
    for x in (20, 40, 60, 80, 100):
        ax.axvline(x, color=GRID, lw=0.5, zorder=0)
    ax.set_ylim(-0.9, n - 0.4)
    ax.set_xlabel('LLM-as-judge score (%)')
    ax.text(1.02, n - 0.25, 'change', transform=ax.get_yaxis_transform(), ha='left', va='bottom', fontsize=6, color=MUTED)
    # legend: open = zero-shot, filled = fine-tuned
    ax.plot([], [], 'o', ms=4, mfc='white', mec=MUTED, mew=1.0, ls='', label='Zero-shot')
    ax.plot([], [], 'o', ms=4, color=MUTED, ls='', label='Fine-tuned on VulnCodeX')
    ax.legend(loc='lower center', bbox_to_anchor=(0.42, 1.0), ncol=2, frameon=False, fontsize=6.3,
              handletextpad=0.3, columnspacing=1.0)
    fig.savefig(OUT)
    fig.savefig(ROOT / 'figures' / 'out' / 'fig_finetune.png', dpi=300)
    print('wrote', OUT)


if __name__ == '__main__':
    main()
