# Figures

Scripts that rebuild the paper's figures and the data behind its tables. Outputs go to `figures/out/`.

| Paper | Script | Reads |
|---|---|---|
| Fig. 1 (pipeline) | drawn by hand: `fig_pipeline.pdf` | |
| Fig. 2, Tables III and VII, numbers in the text | `make_dataset_stats.py` | `data/`, `pipeline/reports/` |
| Fig. 3 (question map) | `question_diversity.py` (sentence embeddings + UMAP) | `data/` |
| Fig. 4 (old and recent CVEs) | `memorisation_figure.py` | `benchmark/*/judged_cve.jsonl` |
| Fig. 5 (ablation) | `ablation_figure.py` | `benchmark/ablation_options/data.json` |
| Fig. 6 (fine-tuning) | `finetune_figure.py` | `finetune/comparison_cve.json` |

Figs. 3, 5 and 6 are drawn with matplotlib and written as PDF directly. Figs. 2 and 4 are written as
pgfplots sources; `export_figures.py` compiles them to PDF with Tectonic (on `PATH`, or set
`TECTONIC`). `prose_numbers.txt` lists every dataset statistic quoted in the paper.

```
python figures/make_dataset_stats.py
python figures/question_diversity.py
python figures/memorisation_figure.py
python figures/ablation_figure.py
python figures/finetune_figure.py
python figures/export_figures.py
```
