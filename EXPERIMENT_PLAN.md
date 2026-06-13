# Concrete Experiment Plan

## Phase 0: Sanity Check

Goal: verify that the PyPI-only pipeline generates the intended views.

Command:

```bash
python scripts/prepare_samples.py \
  --pypi-csv /mnt/data/wangshibo/omni_dataset_stage3/pypi_real_test_balanced_v3.csv \
  --output data/sample_manifest.csv \
  --per-label 20 \
  --seed 7

python scripts/build_ablation_views.py \
  --manifest data/sample_manifest.csv \
  --output data/ablation_views.jsonl
```

Manual checks:

- `data/sample_manifest.csv` has 40 rows.
- `data/ablation_views.jsonl` has 120 rows.
- `mask_suspicious_cues` contains `SUSPICIOUS_CUE_X`.
- `keywords_only` does not include raw code.

## Phase 1: Smoke LLM Run

Goal: test whether the effect exists before scaling.

Run only:

- `original`
- `mask_suspicious_cues`
- `keywords_only`

Expected calls:

```text
40 samples x 3 views = 120 calls per model
```

Decision criteria:

- Strong signal: recall drop from `original` to `mask_suspicious_cues` is at least 0.10.
- Strong signal: `keywords_only` F1 is close to original F1 or creates clear benign false-positive inflation.
- Weak signal: deltas are near zero and error cases are not interpretable.

## Phase 2: Keyword Contribution

Goal: find which lexical cues drive model decisions.

Build per-keyword views:

```bash
python scripts/build_ablation_views.py \
  --manifest data/sample_manifest.csv \
  --output data/keyword_contribution_views.jsonl \
  --include-keyword-contribution
```

Run inference on those views and analyze:

```bash
python scripts/analyze_results.py \
  --predictions results/keyword_contribution_predictions.jsonl \
  --metrics-output tables/keyword_metrics_by_view.csv \
  --cue-output tables/keyword_cue_dependency_summary.csv \
  --keyword-output tables/keyword_contribution.csv \
  --errors-output tables/keyword_error_cases.csv
```

Primary table:

```text
Keyword | Delta Recall | Delta F1
```

## Phase 3: Scale Only If Needed

If Phase 1 and Phase 2 show clear effects, increase the sample size.

Recommended next step:

```text
100 malicious + 100 benign
```

Do not jump directly to the full dataset unless cost, latency, and failure recovery have been checked.

## Paper Message

Target finding:

```text
LLM-based PyPI malware judgments show substantial lexical cue dependency. Masking suspicious cues reduces recall, while keyword-only inputs preserve or recover a meaningful fraction of original performance. Per-keyword ablations identify the cues that most strongly support malicious predictions.
```

