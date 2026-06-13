import argparse
import logging
from pathlib import Path

import pandas as pd

from common import setup_logging


REQUIRED_COLUMNS = {
    "sample_id",
    "package_name",
    "file_source",
    "content",
    "label",
    "ecosystem",
    "language",
}


def read_pypi_source(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"{path} missing columns: {sorted(missing)}")
    df = df.copy()
    df["ecosystem"] = "pypi"
    df["label"] = df["label"].astype(int)
    df["content"] = df["content"].fillna("")
    return df


def balanced_sample(df: pd.DataFrame, per_label: int | None, seed: int) -> pd.DataFrame:
    if per_label is None:
        return df
    parts = []
    for label, group in df.groupby("label", sort=True):
        n = min(per_label, len(group))
        if n < per_label:
            logging.warning("Only %s rows for label=%s", n, label)
        parts.append(group.sample(n=n, random_state=seed))
    return pd.concat(parts, ignore_index=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pypi-csv", required=True)
    parser.add_argument("--output", default="data/sample_manifest.csv")
    parser.add_argument("--per-label", type=int, default=None)
    parser.add_argument("--per-ecosystem-label", type=int, default=None, help="Deprecated alias for --per-label.")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--max-content-chars", type=int, default=20000)
    parser.add_argument("--log", default="logs/prepare_samples.log")
    args = parser.parse_args()

    setup_logging(args.log)
    per_label = args.per_label if args.per_label is not None else args.per_ecosystem_label
    df = read_pypi_source(args.pypi_csv)
    df = df[df["label"].isin([0, 1])].copy()
    df = balanced_sample(df, per_label, args.seed)
    df = df.sort_values(["label", "sample_id"]).reset_index(drop=True)
    df["content"] = df["content"].astype(str).str.slice(0, args.max_content_chars)

    keep = [
        "sample_id",
        "package_name",
        "file_source",
        "ecosystem",
        "language",
        "label",
        "source",
        "content_hash",
        "content",
    ]
    for col in keep:
        if col not in df.columns:
            df[col] = ""

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    df[keep].to_csv(args.output, index=False)
    logging.info("Wrote %s PyPI rows to %s", len(df), args.output)
    logging.info("Counts:\n%s", df.groupby("label").size())


if __name__ == "__main__":
    main()
