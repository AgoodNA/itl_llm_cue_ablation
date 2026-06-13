import argparse
import logging
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

from common import setup_logging


MAIN_VIEWS = [
    "original",
    "mask_suspicious_cues",
    "benign_replacement",
    "mask_behavior_cues",
    "keywords_only",
]


def metrics_for(group: pd.DataFrame) -> dict:
    valid = group.dropna(subset=["prediction"])
    if valid.empty:
        return {"n": 0, "accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "fpr": 0, "fnr": 0}
    y_true = valid["label"].astype(int)
    y_pred = valid["prediction"].astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fpr = fp / (fp + tn) if (fp + tn) else 0
    fnr = fn / (fn + tp) if (fn + tp) else 0
    return {
        "n": len(valid),
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
    }


def grouped_metrics(df: pd.DataFrame, keys: list[str]) -> pd.DataFrame:
    rows = []
    for key_values, group in df.groupby(keys, sort=True):
        if not isinstance(key_values, tuple):
            key_values = (key_values,)
        row = dict(zip(keys, key_values))
        row.update(metrics_for(group))
        rows.append(row)
    return pd.DataFrame(rows)


def cue_dependency_summary(metrics: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for model, group in metrics.groupby("model"):
        by_view = group.set_index("view")
        if "original" not in by_view.index:
            continue
        original = by_view.loc["original"]
        for view in MAIN_VIEWS:
            if view == "original" or view not in by_view.index:
                continue
            current = by_view.loc[view]
            rows.append({
                "model": model,
                "comparison": f"original_minus_{view}",
                "view": view,
                "delta_accuracy": original["accuracy"] - current["accuracy"],
                "delta_precision": original["precision"] - current["precision"],
                "delta_recall": original["recall"] - current["recall"],
                "delta_f1": original["f1"] - current["f1"],
                "delta_fpr": original["fpr"] - current["fpr"],
                "delta_fnr": original["fnr"] - current["fnr"],
            })
    return pd.DataFrame(rows)


def keyword_from_view(view: str) -> str:
    return view.replace("mask_keyword__", "").replace("_", ".")


def keyword_contribution_summary(metrics: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for model, group in metrics.groupby("model"):
        by_view = group.set_index("view")
        if "original" not in by_view.index:
            continue
        original = by_view.loc["original"]
        for view, current in by_view.iterrows():
            if not str(view).startswith("mask_keyword__"):
                continue
            rows.append({
                "model": model,
                "keyword": keyword_from_view(str(view)),
                "view": view,
                "delta_recall": original["recall"] - current["recall"],
                "delta_f1": original["f1"] - current["f1"],
                "original_recall": original["recall"],
                "masked_recall": current["recall"],
                "original_f1": original["f1"],
                "masked_f1": current["f1"],
                "n": current["n"],
            })
    out = pd.DataFrame(rows)
    if not out.empty:
        out = out.sort_values(["delta_recall", "delta_f1", "keyword"], ascending=[False, False, True])
    return out


def false_positive_inflation(df: pd.DataFrame) -> pd.DataFrame:
    pivot = df.pivot_table(
        index=["model", "sample_id"],
        columns="view",
        values="prediction",
        aggfunc="first",
    ).reset_index()
    meta = df.drop_duplicates(["model", "sample_id"])[[
        "model", "sample_id", "package_name", "file_source", "language", "label"
    ]]
    merged = meta.merge(pivot, on=["model", "sample_id"], how="left")
    cols = ["model", "sample_id", "package_name", "file_source", "language", "label", "original", "keywords_only"]
    if "original" not in merged.columns or "keywords_only" not in merged.columns:
        return pd.DataFrame(columns=cols)
    return merged[(merged["label"] == 0) & (merged["original"] == 0) & (merged["keywords_only"] == 1)][cols]


def write_csv(df: pd.DataFrame, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
    logging.info("Wrote %s rows to %s", len(df), path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", default="results/llm_predictions.jsonl")
    parser.add_argument("--metrics-output", default="tables/metrics_by_view.csv")
    parser.add_argument("--cue-output", default="tables/cue_dependency_summary.csv")
    parser.add_argument("--keyword-output", default="tables/keyword_contribution.csv")
    parser.add_argument("--errors-output", default="tables/error_cases.csv")
    parser.add_argument("--log", default="logs/analyze_results.log")
    args = parser.parse_args()

    setup_logging(args.log)
    df = pd.read_json(args.predictions, lines=True)
    df["prediction"] = pd.to_numeric(df["prediction"], errors="coerce")
    df["label"] = df["label"].astype(int)
    valid = df[df["prediction"].isin([0, 1])].copy()
    invalid = df[~df["prediction"].isin([0, 1])].copy()

    metrics = grouped_metrics(valid, ["model", "view"])
    summary = cue_dependency_summary(metrics)
    keyword_summary = keyword_contribution_summary(metrics)
    errors = false_positive_inflation(valid)

    write_csv(metrics, args.metrics_output)
    write_csv(summary, args.cue_output)
    write_csv(keyword_summary, args.keyword_output)
    write_csv(errors, args.errors_output)
    if not invalid.empty:
        logging.warning("%s rows had missing/unparseable predictions", len(invalid))


if __name__ == "__main__":
    main()
