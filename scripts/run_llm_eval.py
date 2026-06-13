import argparse
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from common import append_jsonl, load_done_keys, parse_llm_json, read_jsonl, setup_logging


def load_prompt(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def truncate_middle(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return text[:half] + "\n\n[...TRUNCATED...]\n\n" + text[-half:]


def build_user_prompt(prompt: dict, row: dict, max_chars: int) -> str:
    content = truncate_middle(str(row["view_content"]), max_chars)
    return prompt["user_template"].format(
        ecosystem=row.get("ecosystem", ""),
        package_name=row.get("package_name", ""),
        file_source=row.get("file_source", ""),
        view=row.get("view", ""),
        view_content=content,
    )


def call_openai_model(client: Any, model: str, prompt: dict, row: dict, max_chars: int, temperature: float, max_tokens: int = 64) -> str:
    user = build_user_prompt(prompt, row, max_chars)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": prompt["system"]},
            {"role": "user", "content": user},
        ],
        temperature=temperature,
        response_format={"type": "json_object"},
        max_tokens=max_tokens,
    )
    return response.choices[0].message.content or ""



def dtype_from_arg(dtype: str) -> Any:
    import torch

    if dtype == "bfloat16":
        return torch.bfloat16
    if dtype == "float16":
        return torch.float16
    return torch.float32


def load_hf_model(args: argparse.Namespace) -> tuple[Any, Any, Any]:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    if not args.hf_model_path:
        raise ValueError("--hf-model-path is required when --backend hf")

    device = torch.device(f"cuda:{args.gpu_idx}" if torch.cuda.is_available() else "cpu")
    tokenizer = AutoTokenizer.from_pretrained(
        args.hf_model_path,
        trust_remote_code=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        args.hf_model_path,
        device_map={"": args.gpu_idx} if torch.cuda.is_available() else None,
        torch_dtype=dtype_from_arg(args.dtype),
        trust_remote_code=True,
    ).eval()
    return tokenizer, model, device


def call_hf_model(tokenizer: Any, model: Any, device: Any, prompt_text: str, max_new_tokens: int) -> str:
    import torch

    if hasattr(tokenizer, "apply_chat_template"):
        messages = [
            {"role": "user", "content": prompt_text},
        ]
        try:
            text = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=False,
            )
        except TypeError:
            text = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )
    else:
        text = prompt_text

    inputs = tokenizer(text, return_tensors="pt")
    inputs = {k: v.to(device) for k, v in inputs.items()}
    pad_token_id = tokenizer.eos_token_id
    if pad_token_id is None:
        pad_token_id = tokenizer.pad_token_id

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            do_sample=False,
            max_new_tokens=max_new_tokens,
            pad_token_id=pad_token_id,
        )
    new_tokens = outputs[0][inputs["input_ids"].shape[-1]:]
    return tokenizer.decode(new_tokens, skip_special_tokens=True)


def parsed_output_fields(parsed: dict) -> dict:
    return {
        "parsed_prediction": parsed.get("prediction"),
        "parsed_confidence": parsed.get("confidence", 0.0),
        "parsed_reason": parsed.get("reason", ""),
        "parsed_signals": parsed.get("signals", []),
        "parse_ok": parsed.get("parse_ok", False),
        # Backward-compatible aliases used by analyze_results.py.
        "prediction": parsed.get("prediction"),
        "confidence": parsed.get("confidence", 0.0),
        "reason": parsed.get("reason", ""),
        "signals": parsed.get("signals", []),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=["openai", "hf"], default="openai")
    parser.add_argument("--views", default="data/ablation_views.jsonl")
    parser.add_argument("--output", default="results/llm_predictions.jsonl")
    parser.add_argument("--prompt", default="prompts/classify_package.json")
    parser.add_argument("--model", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--max-content-chars", type=int, default=16000)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--sleep", type=float, default=1.0)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--hf-model-path", default=None)
    parser.add_argument("--gpu-idx", type=int, default=0)
    parser.add_argument("--dtype", choices=["bfloat16", "float16", "float32"], default="bfloat16")
    parser.add_argument("--max-new-tokens", type=int, default=512)
    parser.add_argument("--log", default="logs/run_llm_eval.log")
    args = parser.parse_args()

    setup_logging(args.log)
    prompt = load_prompt(args.prompt)

    client = None
    tokenizer = None
    hf_model = None
    device = None

    if args.backend == "openai":
        from openai import OpenAI

        model_name = args.model or os.environ.get("MODEL_NAME")
        if not model_name:
            raise ValueError("Provide --model or MODEL_NAME")
        client = OpenAI(
            api_key=os.environ.get("OPENAI_API_KEY", ""),
            base_url=args.base_url or os.environ.get("OPENAI_BASE_URL"),
        )
    else:
        tokenizer, hf_model, device = load_hf_model(args)
        model_name = args.model or Path(args.hf_model_path).name

    done = load_done_keys(args.output, ["sample_id", "view", "model"])

    processed = 0
    for row in read_jsonl(args.views):
        if args.limit is not None and processed >= args.limit:
            break
        key = (row["sample_id"], row["view"], model_name)
        if key in done:
            continue

        result = {**{k: row.get(k) for k in [
            "sample_id",
            "package_name",
            "file_source",
            "ecosystem",
            "language",
            "label",
            "source",
            "content_hash",
            "view",
        ]}, "model": model_name}
        raw = ""
        error = ""

        for attempt in range(1, args.max_retries + 1):
            try:
                if args.backend == "openai":
                    raw = call_openai_model(client,model_name,prompt,row,args.max_content_chars,args.temperature,args.max_new_tokens)
                else:
                    prompt_text = build_user_prompt(prompt, row, args.max_content_chars)
                    raw = call_hf_model(tokenizer, hf_model, device, prompt_text, args.max_new_tokens)
                break
            except Exception as exc:
                error = str(exc)
                logging.warning("Attempt %s failed for %s %s: %s", attempt, row["sample_id"], row["view"], exc)
                time.sleep(args.sleep * attempt)

        parsed = parse_llm_json(raw) if raw else {
            "prediction": None,
            "confidence": 0.0,
            "reason": "",
            "signals": [],
            "parse_ok": False,
        }
        result.update(parsed_output_fields(parsed))
        result["raw_response"] = raw
        result["error"] = error if not raw else ""
        append_jsonl(args.output, result)
        processed += 1
        logging.info("Saved %s %s prediction=%s", row["sample_id"], row["view"], result["parsed_prediction"])


if __name__ == "__main__":
    main()
