# ITL LLM Cue Ablation

This project studies whether LLMs detect malicious PyPI packages through genuine behavioral reasoning or through lexical cues.

The revised scope is PyPI-only. npm is intentionally dropped from the main study because `package.json` metadata can introduce dataset artifacts, while the target ITL Letter needs a compact, cleaner story around executable Python package behavior.

This is not a benchmark paper, not a detector-comparison paper, and not an OMNI result reproduction. The goal is to produce a small explainability finding about LLM behavior under controlled cue removal.

## Revised Research Question

Do LLMs detect malicious PyPI packages through genuine behavioral reasoning, or through lexical cues?

## Dataset

Use only:

```text
pypi_real_test_balanced_v3.csv
```

Expected columns include:

- `sample_id`
- `package_name`
- `file_source`
- `content`
- `label`
- `source`
- `ecosystem`
- `language`
- `content_hash`

The scripts force `ecosystem=pypi` in the manifest.

## Main Views

The main study uses:

- `original`: original PyPI file content.
- `mask_suspicious_cues`: masks suspicious lexical cues, suspicious URLs, long base64-like strings, and long encoded strings.
- `keywords_only`: provides only extracted suspicious keywords.

Optional:

- `mask_behavior_cues`: masks behavior-oriented API words such as `subprocess`, `requests`, `socket`, and `urllib`.

Removed from the main study:

- npm data.
- ecosystem cue masking.
- npm-specific analyses.

## Suspicious Cue Dictionary

The current suspicious cue list includes:

```text
subprocess
popen
os.system
system
powershell
cmd.exe
encodedcommand
invoke-webrequest
invoke-expression
iex
curl
wget
certutil
base64
b64decode
b64encode
socket
requests
urllib
discord
discordapp
cdn.discordapp
pastebin
webhook
proton.me
```

It also detects:

- long base64-like strings
- long hex/encoded strings
- suspicious URLs involving Discord, Pastebin, webhook-like endpoints, URL shorteners, ngrok, Proton, and raw GitHub content

All matches are replaced with `SUSPICIOUS_CUE_X`.

## Keyword Contribution Analysis

This is a main analysis, not a side note.

For each suspicious cue present in the sample:

1. Build a view that masks only that cue.
2. Run the same LLM inference prompt.
3. Compare against `original`.
4. Report:

```text
Keyword | Delta Recall | Delta F1
```

The output file is:

```text
tables/keyword_contribution.csv
```

This analysis is meant to identify which lexical cues most strongly support LLM malicious predictions.

## Smoke Test Plan

Before any large-scale run:

- 20 malicious PyPI samples
- 20 benign PyPI samples
- Views:
  - `original`
  - `mask_suspicious_cues`
  - `keywords_only`

Run this first and inspect:

- Does recall drop after suspicious cue masking?
- Does `keywords_only` recover a large fraction of original F1?
- Are benign packages pushed to malicious under `keywords_only`?
- Are keyword contribution deltas non-trivial for cues such as `subprocess`, `powershell`, `base64`, `discordapp`, and `requests`?

Only scale up if the smoke test shows a meaningful effect.

## Pipeline

```bash
cd /Users/teddy/itl_llm_cue_ablation
```

Prepare the 20 benign + 20 malicious smoke-test manifest:

```bash
python scripts/prepare_samples.py \
  --pypi-csv /mnt/data/wangshibo/omni_dataset_stage3/pypi_real_test_balanced_v3.csv \
  --output data/sample_manifest.csv \
  --per-label 20 \
  --seed 7
```

Build only the main smoke-test views:

```bash
python scripts/build_ablation_views.py \
  --manifest data/sample_manifest.csv \
  --output data/ablation_views.jsonl
```

Run LLM inference:

```bash
OPENAI_API_KEY=... OPENAI_BASE_URL=... MODEL_NAME=... \
python scripts/run_llm_eval.py \
  --views data/ablation_views.jsonl \
  --output results/llm_predictions.jsonl \
  --prompt prompts/classify_package.json
```

Analyze:

```bash
python scripts/analyze_results.py \
  --predictions results/llm_predictions.jsonl \
  --metrics-output tables/metrics_by_view.csv \
  --cue-output tables/cue_dependency_summary.csv \
  --keyword-output tables/keyword_contribution.csv \
  --errors-output tables/error_cases.csv
```

Plot:

```bash
python scripts/plot_results.py \
  --metrics tables/metrics_by_view.csv \
  --cue-summary tables/cue_dependency_summary.csv \
  --keyword-summary tables/keyword_contribution.csv \
  --output-dir figures
```

## Keyword Contribution Run

After the first smoke-test effect looks meaningful, build per-keyword masking views:

```bash
python scripts/build_ablation_views.py \
  --manifest data/sample_manifest.csv \
  --output data/keyword_contribution_views.jsonl \
  --include-keyword-contribution
```

Then run inference on `data/keyword_contribution_views.jsonl` and analyze as above.

Do not start a large-scale run automatically. Inspect the smoke-test outputs first.

## Environment

Target:

- Python 3.11
- pandas
- numpy
- scikit-learn
- matplotlib
- openai

The LLM runner reads:

- `OPENAI_API_KEY`
- `OPENAI_BASE_URL`
- `MODEL_NAME`

# ITL LLM Cue Ablation

This project studies whether LLMs detect malicious PyPI packages through genuine behavioral reasoning or through lexical cues.

The revised scope is PyPI-only. npm is intentionally dropped from the main study because `package.json` metadata can introduce dataset artifacts, while the target ITL Letter needs a compact, cleaner story around executable Python package behavior.

This is not a benchmark paper, not a detector-comparison paper, and not an OMNI result reproduction. The goal is to produce a small explainability finding about LLM behavior under controlled cue removal.

## Revised Research Question

Do LLMs detect malicious PyPI packages through genuine behavioral reasoning, or through lexical cues?

## Dataset

Use only:

```text
pypi_real_test_balanced_v3.csv
```

Expected columns include:

- `sample_id`
- `package_name`
- `file_source`
- `content`
- `label`
- `source`
- `ecosystem`
- `language`
- `content_hash`

The scripts force `ecosystem=pypi` in the manifest.

## Main Views

The main study uses:

- `original`: original PyPI file content.
- `mask_suspicious_cues`: masks suspicious lexical cues, suspicious URLs, long base64-like strings, and long encoded strings.
- `keywords_only`: provides only extracted suspicious keywords.

Optional:

- `mask_behavior_cues`: masks behavior-oriented API words such as `subprocess`, `requests`, `socket`, and `urllib`.

Removed from the main study:

- npm data.
- ecosystem cue masking.
- npm-specific analyses.

## Suspicious Cue Dictionary

The current suspicious cue list includes:

```text
subprocess
popen
os.system
system
powershell
cmd.exe
encodedcommand
invoke-webrequest
invoke-expression
iex
curl
wget
certutil
base64
b64decode
b64encode
socket
requests
urllib
discord
discordapp
cdn.discordapp
pastebin
webhook
proton.me
```

It also detects:

- long base64-like strings
- long hex/encoded strings
- suspicious URLs involving Discord, Pastebin, webhook-like endpoints, URL shorteners, ngrok, Proton, and raw GitHub content

All matches are replaced with `SUSPICIOUS_CUE_X`.

## Keyword Contribution Analysis

This is a main analysis, not a side note.

For each suspicious cue present in the sample:

1. Build a view that masks only that cue.
2. Run the same LLM inference prompt.
3. Compare against `original`.
4. Report:

```text
Keyword | Delta Recall | Delta F1
```

The output file is:

```text
tables/keyword_contribution.csv
```

This analysis is meant to identify which lexical cues most strongly support LLM malicious predictions.

## Smoke Test Plan

Before any large-scale run:

- 20 malicious PyPI samples
- 20 benign PyPI samples
- Views:
  - `original`
  - `mask_suspicious_cues`
  - `keywords_only`

Run this first and inspect:

- Does recall drop after suspicious cue masking?
- Does `keywords_only` recover a large fraction of original F1?
- Are benign packages pushed to malicious under `keywords_only`?
- Are keyword contribution deltas non-trivial for cues such as `subprocess`, `powershell`, `base64`, `discordapp`, and `requests`?

Only scale up if the smoke test shows a meaningful effect.

## Pipeline

```bash
cd /Users/teddy/itl_llm_cue_ablation
```

Prepare the 20 benign + 20 malicious smoke-test manifest:

```bash
python scripts/prepare_samples.py \
  --pypi-csv /mnt/data/wangshibo/omni_dataset_stage3/pypi_real_test_balanced_v3.csv \
  --output data/sample_manifest.csv \
  --per-label 20 \
  --seed 7
```

Build only the main smoke-test views:

```bash
python scripts/build_ablation_views.py \
  --manifest data/sample_manifest.csv \
  --output data/pypi_ablation_views.jsonl
```

Run LLM inference:

```bash
OPENAI_API_KEY=... OPENAI_BASE_URL=... MODEL_NAME=... \
python scripts/run_llm_eval.py \
  --views data/pypi_ablation_views.jsonl \
  --output results/llm_predictions.jsonl \
  --prompt prompts/classify_package.json
```

DeepSeek local HuggingFace smoke test:

```bash
python scripts/run_llm_eval.py \
  --backend hf \
  --hf-model-path /mnt/home/wangshibo/.cache/huggingface/hub/models--deepseek-ai--DeepSeek-R1-Distill-Llama-8B/snapshots/6a6f4aa4197940add57724a7707d069478df56b1 \
  --gpu-idx 0 \
  --views data/pypi_ablation_views.jsonl \
  --output results/deepseek_pypi_smoke_predictions.jsonl \
  --prompt prompts/classify_package.json \
  --limit 30 \
  --max-new-tokens 512
```

This command is intended for a 10 PyPI samples x 3 views smoke test. Do not use it to start a large-scale run before inspecting the smoke-test outputs.

Analyze:

```bash
python scripts/analyze_results.py \
  --predictions results/llm_predictions.jsonl \
  --metrics-output tables/metrics_by_view.csv \
  --cue-output tables/cue_dependency_summary.csv \
  --keyword-output tables/keyword_contribution.csv \
  --errors-output tables/error_cases.csv
```

Plot:

```bash
python scripts/plot_results.py \
  --metrics tables/metrics_by_view.csv \
  --cue-summary tables/cue_dependency_summary.csv \
  --keyword-summary tables/keyword_contribution.csv \
  --output-dir figures
```

## Keyword Contribution Run

After the first smoke-test effect looks meaningful, build per-keyword masking views:

```bash
python scripts/build_ablation_views.py \
  --manifest data/sample_manifest.csv \
  --output data/keyword_contribution_views.jsonl \
  --include-keyword-contribution
```

Then run inference on `data/keyword_contribution_views.jsonl` and analyze as above.

Do not start a large-scale run automatically. Inspect the smoke-test outputs first.

## Environment

Target:

- Python 3.11
- pandas
- numpy
- scikit-learn
- matplotlib
- openai
- torch
- transformers

The LLM runner reads:

- `OPENAI_API_KEY`
- `OPENAI_BASE_URL`
- `MODEL_NAME`

The HuggingFace backend does not require an OpenAI-compatible server, but it does require a local model snapshot and enough GPU memory for the selected model. Load only one model at a time, and begin with the `--limit 30` smoke test.
