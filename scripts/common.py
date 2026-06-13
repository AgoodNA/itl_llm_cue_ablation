import csv
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def setup_logging(log_path: Optional[str]) -> None:
    handlers = [logging.StreamHandler()]
    if log_path:
        ensure_parent(log_path)
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers,
    )


def read_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def append_jsonl(path: str, row: Dict[str, Any]) -> None:
    ensure_parent(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_done_keys(path: str, fields: List[str]) -> set:
    if not os.path.exists(path):
        return set()
    done = set()
    for row in read_jsonl(path):
        done.add(tuple(row.get(f) for f in fields))
    return done


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def normalize_prediction(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return 1 if int(value) == 1 else 0 if int(value) == 0 else None
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"1", "malicious", "malware", "true", "yes"}:
            return 1
        if v in {"0", "benign", "clean", "false", "no"}:
            return 0
    return None


def parse_llm_json(text: str) -> Dict[str, Any]:
    raw = text.strip()
    candidates = []

    bare_prediction = normalize_prediction(raw)
    if bare_prediction is not None:
        return {
            "prediction": bare_prediction,
            "confidence": 0.0,
            "reason": "",
            "signals": [],
            "parse_ok": True,
        }

    fenced = re.findall(r"```(?:json)?\s*(.*?)```", raw, flags=re.S | re.I)
    candidates.extend(s.strip() for s in fenced)
    decoder = json.JSONDecoder()
    index = 0
    while index < len(raw):
        start = raw.find("{", index)
        if start == -1:
            break
        try:
            _, end = decoder.raw_decode(raw[start:])
            candidates.append(raw[start:start + end])
            index = start + end
        except json.JSONDecodeError:
            index = start + 1
    obj_matches = re.findall(r"\{.*?\}", raw, flags=re.S)
    candidates.extend(s.strip() for s in obj_matches)
    candidates.append(raw)

    for candidate in reversed(candidates):
        try:
            parsed = json.loads(candidate)
            if not isinstance(parsed, dict):
                pred = normalize_prediction(parsed)
                parsed = {}
            elif "prediction" in parsed:
                pred = normalize_prediction(parsed.get("prediction"))
            else:
                pred = normalize_prediction(parsed.get("malicious"))
            if pred is None:
                continue
            confidence = parsed.get("confidence", 0.0)
            try:
                confidence = float(confidence)
            except Exception:
                confidence = 0.0
            signals = parsed.get("signals", [])
            if isinstance(signals, str):
                signals = [signals]
            elif not isinstance(signals, list):
                signals = []
            return {
                "prediction": pred,
                "confidence": max(0.0, min(1.0, confidence)),
                "reason": str(parsed.get("reason", "")),
                "signals": signals,
                "parse_ok": True,
            }
        except Exception:
            continue

    return {
        "prediction": None,
        "confidence": 0.0,
        "reason": "",
        "signals": [],
        "parse_ok": False,
    }
