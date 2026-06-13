import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


MAIN_VIEWS = [
    "original",
    "mask_suspicious_cues",
    "benign_replacement",
    "mask_behavior_cues",
    "keywords_only",
]


def savefig(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(path, dpi=220)
    if path.suffix.lower() == ".png":
        plt.savefig(path.with_suffix(".pdf"))
    plt.close()


def plot_f1_by_view(metrics: pd.DataFrame, out_dir: Path) -> None:
    for model, group in metrics.groupby("model"):
        group = group[group["view"].isin(MAIN_VIEWS)].copy()
        group["view"] = pd.Categorical(group["view"], MAIN_VIEWS, ordered=True)
        group = group.sort_values("view")
        labels = [str(r.view) for r in group.itertuples()]
        plt.figure(figsize=(max(7, len(labels) * 0.9), 4.5))
        plt.bar(labels, group["f1"])
        plt.ylim(0, 1)
        plt.ylabel("F1")
        plt.title(f"PyPI F1 by view: {model}")
        plt.xticks(rotation=35, ha="right")
        savefig(out_dir / "f1_by_view.png")
        break


def plot_recall_drop(summary: pd.DataFrame, out_dir: Path) -> None:
    if summary.empty:
        return
    focus = summary[summary["view"].isin(["mask_suspicious_cues", "mask_behavior_cues", "keywords_only"])].copy()
    if focus.empty:
        return
    labels = [str(r.view) for r in focus.itertuples()]
    plt.figure(figsize=(max(7, len(labels) * 0.9), 4.5))
    plt.bar(labels, focus["delta_recall"])
    plt.axhline(0, color="black", linewidth=0.8)
    plt.ylabel("Recall(original) - Recall(view)")
    plt.title("PyPI recall drop under cue ablations")
    plt.xticks(rotation=35, ha="right")
    savefig(out_dir / "recall_drop_by_view.png")


def plot_keywords_vs_original(metrics: pd.DataFrame, out_dir: Path) -> None:
    focus = metrics[metrics["view"].isin(["original", "keywords_only"])].copy()
    if focus.empty:
        return
    pivot = focus.pivot_table(index=["model"], columns="view", values="f1", aggfunc="first").reset_index()
    if "original" not in pivot.columns or "keywords_only" not in pivot.columns:
        return
    x = range(len(pivot))
    width = 0.35
    labels = [str(r.model) for r in pivot.itertuples()]
    plt.figure(figsize=(max(6, len(labels) * 1.0), 4))
    plt.bar([i - width / 2 for i in x], pivot["original"], width, label="original")
    plt.bar([i + width / 2 for i in x], pivot["keywords_only"], width, label="keywords_only")
    plt.ylim(0, 1)
    plt.ylabel("F1")
    plt.title("Keywords-only versus original")
    plt.xticks(list(x), labels)
    plt.legend()
    savefig(out_dir / "keywords_only_vs_original.png")


def plot_keyword_contribution(keyword_summary: pd.DataFrame, out_dir: Path, top_n: int = 12) -> None:
    if keyword_summary.empty:
        return
    focus = keyword_summary.sort_values(["delta_recall", "delta_f1"], ascending=False).head(top_n)
    plt.figure(figsize=(max(7, len(focus) * 0.65), 4.2))
    plt.bar(focus["keyword"], focus["delta_recall"])
    plt.axhline(0, color="black", linewidth=0.8)
    plt.ylabel("Delta recall")
    plt.title("Keyword contribution")
    plt.xticks(rotation=45, ha="right")
    savefig(out_dir / "keyword_contribution.png")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metrics", default="tables/metrics_by_view.csv")
    parser.add_argument("--cue-summary", default="tables/cue_dependency_summary.csv")
    parser.add_argument("--keyword-summary", default="tables/keyword_contribution.csv")
    parser.add_argument("--output-dir", default="figures")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    metrics = pd.read_csv(args.metrics)
    summary = pd.read_csv(args.cue_summary)
    keyword_summary = pd.read_csv(args.keyword_summary) if Path(args.keyword_summary).exists() else pd.DataFrame()
    plot_f1_by_view(metrics, out_dir)
    plot_recall_drop(summary, out_dir)
    plot_keywords_vs_original(metrics, out_dir)
    plot_keyword_contribution(keyword_summary, out_dir)


if __name__ == "__main__":
    main()
