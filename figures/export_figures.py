"""Compile the paper's TikZ/pgfplots figures into standalone PDFs next to the manuscript.

Usage:  python3 scripts/export_figures.py
Reads:  figures/out/<name>.tex   (written by make_dataset_stats.py and memorisation_figure.py)
Writes: figures/out/fig_<name>.pdf
Needs:  Tectonic (https://tectonic-typesetting.github.io) on PATH, or its path in $TECTONIC

The manuscript includes only PDFs (\\includegraphics) and holds every caption itself, so the paper folder
can be uploaded to Overleaf as it is. Each source file is a figure float; this script keeps what is drawn
(colour definitions and tikzpictures), drops the float, \\centering, \\caption and \\label, and compiles it
at the paper's width: \\textwidth for figure*, \\columnwidth for figure (IEEEtran conference with 0.75in
margins). Fonts: TeX Gyre Termes, the Times clone used for local builds of the paper.
Figures drawn with matplotlib (question map, ablation) are written to paper/ by their own scripts.
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / 'figures' / 'out'
PAPER = ROOT / 'figures' / 'out'
TECTONIC = os.environ.get('TECTONIC', 'tectonic')
# The pipeline figure (fig_pipeline_v4.pdf) is designed by hand; the earlier TikZ versions are in archive/.
FIGURES = {'dataset_stats_figure': 'fig_dataset_stats', 'memorisation_figure': 'fig_memorisation'}
TEXTWIDTH, COLUMNWIDTH = '505.89pt', '246.94499pt'

PREAMBLE = r"""\documentclass[border=1pt]{standalone}
\usepackage{xcolor}
\usepackage{pgfplots}
\usepgfplotslibrary{groupplots}
\pgfplotsset{compat=1.16}
\usetikzlibrary{shapes.geometric,arrows.meta,calc,positioning}
\usepackage{xspace}
\usepackage{pifont}
\usepackage{fontspec}
\setmainfont{texgyretermes}[Extension=.otf, UprightFont=*-regular, BoldFont=*-bold, ItalicFont=*-italic, BoldItalicFont=*-bolditalic]
\newcommand{\dsname}{VulnCodeX\xspace}
"""


def drop_command(text, name):
    """Remove every \\name{...} with balanced braces."""
    out, i = [], 0
    while True:
        j = text.find('\\' + name + '{', i)
        if j < 0:
            return ''.join(out) + text[i:]
        out.append(text[i:j])
        k, depth = j + len(name) + 2, 1
        while depth:
            depth += {'{': 1, '}': -1}.get(text[k], 0)
            k += 1
        i = k


def body_of(src):
    text = src.read_text()
    wide = '\\begin{figure*}' in text
    text = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('%'))
    text = re.sub(r'\\(begin|end)\{figure\*?\}(\[[^\]]*\])?', '', text)
    text = text.replace('\\centering', '')
    for cmd in ('caption', 'label'):
        text = drop_command(text, cmd)
    return text.strip(), wide


def main():
    for name, out in FIGURES.items():
        body, wide = body_of(SRC / f'{name}.tex')
        width = TEXTWIDTH if wide else COLUMNWIDTH
        # lengths are set after \begin{document}: the standalone class resets them there
        doc = (PREAMBLE + '\\begin{document}\n'
               f'\\setlength{{\\textwidth}}{{{TEXTWIDTH}}}\\setlength{{\\columnwidth}}{{{COLUMNWIDTH}}}'
               f'\\setlength{{\\linewidth}}{{{width}}}%\n{body}\n\\end{{document}}\n')
        with tempfile.TemporaryDirectory() as tmp:
            tex = Path(tmp) / f'{out}.tex'
            tex.write_text(doc)
            run = subprocess.run([TECTONIC, '--chatter', 'minimal', str(tex)], capture_output=True, text=True)
            if run.returncode:
                raise SystemExit(f'{name}: compile failed\n{run.stderr[-2000:]}')
            shutil.copy(Path(tmp) / f'{out}.pdf', PAPER / f'{out}.pdf')
        print(f'{name} -> paper/{out}.pdf ({"text" if wide else "column"} width)')


if __name__ == '__main__':
    main()
