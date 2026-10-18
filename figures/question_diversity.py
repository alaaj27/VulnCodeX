"""C3: how diverse are the questions and answers? Statistics and an embedding map of the questions.

Usage:  python pipeline/question_diversity.py
Reads:  data/vulncodex.jsonl.gz; topic rules from make_dataset_stats.py
Writes: figures/out/question_diversity.json            (all numbers quoted in the paper)
        figures/out/fig_question_map.pdf                 (the figure; generated -- do not edit by hand)
        figures/out/question_map_figure.tex      (a float with a caption drafted from the data; the
                                                   manuscript holds its own caption)

Questions are compared after lower-casing and collapsing whitespace, with the code placeholder removed.
"Opening" questions are the first question of each conversation; "follow-up" questions are the rest.
Embedding map: every distinct question is embedded with all-MiniLM-L6-v2 (sentence-transformers, CPU) and
projected to 2-D with UMAP (cosine, 30 neighbours, seed 0). Panel (a) shows the distinct opening
questions and panel (b) the distinct follow-up questions on the same map; colour = topic (the six most
frequent topics, the rest pooled as "Other"), and point area grows with log frequency. The legend names
every colour (in-map labels overlapped where the topic clusters meet).
"""
import collections
import json
import math
import re
import sys
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from vulncodex import load_records  # noqa: E402
from vulncodex.topics import topic_of  # noqa: E402

OUT_JSON = ROOT / 'figures' / 'out' / 'question_diversity.json'
OUT_PDF = ROOT / 'figures' / 'out' / 'fig_question_map.pdf'
OUT_TEX = ROOT / 'figures' / 'out' / 'question_map_figure.tex'
# Categorical slots 1-6 of the dataviz reference palette, in fixed order (validated: all checks pass on a
# light surface; three slots are below 3:1 contrast, so the legend gives every colour a text label).
SLOTS = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300']
OTHER = '#b4b2ab'
INK, MUTED = '#0b0b0b', '#52514e'


def norm(text):
    return re.sub(r'\s+', ' ', text.replace('<code_sequence>', '')).strip().lower()


def distinct_n(texts, n):
    grams, total = set(), 0
    for t in texts:
        w = t.split()
        g = [tuple(w[i:i + n]) for i in range(len(w) - n + 1)]
        grams.update(g)
        total += len(g)
    return len(grams) / max(total, 1)


def coverage(counter, k):
    return 100 * sum(c for _, c in counter.most_common(k)) / sum(counter.values())


def main():
    records = load_records()
    opening, follow, answers = collections.Counter(), collections.Counter(), []
    for r in records:
        qs = [norm(t['value']) for t in r['conversations'][0::2]]
        opening[qs[0]] += 1
        follow.update(qs[1:])
        answers += [norm(t['value']) for t in r['conversations'][1::2]]
    allq = opening + follow
    ans_counter = collections.Counter(answers)
    stats = {
        'questions': sum(allq.values()), 'distinct_questions': len(allq),
        'opening': {'count': sum(opening.values()), 'distinct': len(opening),
                    'top5_coverage_%': round(coverage(opening, 5), 1), 'top20_coverage_%': round(coverage(opening, 20), 1),
                    'top5': [[q, c] for q, c in opening.most_common(5)]},
        'follow_up': {'count': sum(follow.values()), 'distinct': len(follow),
                      'top5_coverage_%': round(coverage(follow, 5), 1), 'top20_coverage_%': round(coverage(follow, 20), 1),
                      'top5': [[q, c] for q, c in follow.most_common(5)]},
        'questions_seen_once_%': round(100 * sum(1 for c in allq.values() if c == 1) / len(allq), 1),
        'answers': {'count': len(answers), 'distinct': len(ans_counter),
                    'distinct_%': round(100 * len(ans_counter) / len(answers), 1)},
        'distinct_2': {'questions': round(distinct_n(list(allq.elements()), 2), 3),
                       'answers': round(distinct_n(answers, 2), 3)},
    }

    # ---- embedding map of the distinct questions
    from sentence_transformers import SentenceTransformer
    import umap
    texts = list(allq)
    model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')
    emb = model.encode(texts, batch_size=512, show_progress_bar=False, normalize_embeddings=True)
    xy = umap.UMAP(n_components=2, n_neighbors=30, min_dist=0.1, metric='cosine', random_state=0).fit_transform(emb)
    topics = [topic_of(t) for t in texts]
    # the six topics with the most questions (not distinct questions), as in the topic panel of Figure 2
    freq = collections.Counter()
    for t, q in zip(topics, texts):
        freq[t] += allq[q]
    top6 = [t for t, _ in collections.Counter({t: c for t, c in freq.items() if t != 'Other'}).most_common(6)]
    colour = {t: SLOTS[i] for i, t in enumerate(top6)}
    group = [t if t in colour else 'Other' for t in topics]
    stats['map'] = {'embedding_model': 'all-MiniLM-L6-v2', 'umap': 'cosine, n_neighbors=30, min_dist=0.1, seed 0',
                    'topics_coloured': top6, 'pooled_as_other': sorted(set(topics) - set(top6))}
    OUT_JSON.write_text(json.dumps(stats, indent=1) + '\n')

    plt.rcParams.update({'font.family': 'serif', 'font.size': 7, 'axes.edgecolor': '#c3c2b7'})
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 3.1), sharex=True, sharey=True)
    for ax, (title, counter) in zip(axes, [('(a) Opening questions', opening), ('(b) Follow-up questions', follow)]):
        ax.scatter(xy[:, 0], xy[:, 1], s=0.6, c='#e7e6e1', linewidths=0, rasterized=True)   # all questions, for context
        idx = [i for i, t in enumerate(texts) if t in counter]
        for g in ['Other'] + top6:                                                            # Other first, underneath
            sel = [i for i in idx if group[i] == g]
            if not sel:
                continue
            size = [1.5 + 2.2 * math.log10(counter[texts[i]]) ** 2 for i in sel]
            ax.scatter(xy[sel, 0], xy[sel, 1], s=size, c=colour.get(g, OTHER), alpha=0.75, linewidths=0, rasterized=True)
        n_distinct = len(idx)
        ax.set_title(f'{title}: {n_distinct:,} distinct', fontsize=8, color=INK)
        ax.set_xticks([]); ax.set_yticks([])
        for s in ax.spines.values():
            s.set_linewidth(0.5)
    handles = [plt.Line2D([], [], marker='o', ls='', color=colour[t], label=t, ms=4) for t in top6]
    handles.append(plt.Line2D([], [], marker='o', ls='', color=OTHER, label='Other', ms=4))
    fig.legend(handles=handles, loc='lower center', ncol=7, frameon=False, fontsize=7, labelcolor=MUTED,
               bbox_to_anchor=(0.5, -0.01))
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(OUT_PDF, dpi=300)

    o, f = stats['opening'], stats['follow_up']
    OUT_TEX.write_text(rf"""% Generated by scripts/question_diversity.py -- do not edit by hand.
\begin{{figure*}}[t]
\centering
\includegraphics[width=\textwidth]{{fig_question_map.pdf}}
\caption{{Map of the {stats['distinct_questions']:,} distinct questions (sentence embeddings projected with UMAP;
nearby points ask similar things). Colour is the question topic; point area grows with how often a question
occurs. (a)~Opening questions are concentrated: the five most frequent cover {o['top5_coverage_%']}\% of the
{o['count']:,} conversations. (b)~Follow-up questions spread over the whole map: {f['distinct']:,} distinct
questions among {f['count']:,}, the five most frequent covering {f['top5_coverage_%']}\%.}}
\label{{fig:question-map}}
\end{{figure*}}
""")
    print(json.dumps({k: v for k, v in stats.items() if k != 'map'}, indent=1))


if __name__ == '__main__':
    main()
