# URL model card (auto-generated)

Rows: 303,000 (train 242,800, held-out real test 59,643).
Split: GroupShuffleSplit by registered domain, 80/20.

| model | accuracy | precision | recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|---|
| device (GB, ONNX ~300KB) | 0.9009 | 0.9116 | 0.885 | 0.8981 | 0.9682 | 0.0836 |
| ensemble (RF+HGB+LR) | 0.9088 | 0.9166 | 0.8969 | 0.9066 | 0.9722 | 0.0795 |

**Read the numbers with care.** The benign class is mostly *bare popular domains* (some given
synthetic realistic paths) while the phishing class is mostly *real phishing URLs*. High scores here
partly measure "popular domain vs. throw-away URL". Add PhiUSIIL / LegitPhish / your own benign
URLs-with-paths (see data/DATASETS.md) and retrain before trusting the figures. See `metrics_url.json`
for the bias checks (`kind=*`, `phishing_path_stripped_recall`).
