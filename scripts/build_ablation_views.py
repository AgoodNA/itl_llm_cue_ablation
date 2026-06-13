import argparse
import ast
import hashlib
import io
import logging
import random
import re
import tokenize
from typing import Dict, Iterable, List, Tuple

import pandas as pd

from common import append_jsonl, load_done_keys, setup_logging


SUSPICIOUS_CUES = [
    "cdn.discordapp",
    "discordapp",
    "invoke-webrequest",
    "invoke-expression",
    "encodedcommand",
    "os.system",
    "cmd.exe",
    "powershell",
    "subprocess",
    "certutil",
    "b64decode",
    "b64encode",
    "pastebin",
    "proton.me",
    "requests",
    "discord",
    "webhook",
    "base64",
    "socket",
    "urllib",
    "popen",
    "system",
    "curl",
    "wget",
    "iex",
]

BEHAVIOR_CUES = [
    "subprocess",
    "os.system",
    "popen",
    "system",
    "requests",
    "socket",
    "urllib",
    "open",
    "write",
    "connect",
    "exec",
    "eval",
]

PATTERN_CUES = {
    "long_base64": re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{80,}={0,2})(?![A-Za-z0-9+/=])"),
    "long_hex": re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{96,})(?![A-Fa-f0-9])"),
    "suspicious_url": re.compile(
        r"https?://[^\s'\"<>]*(?:discord(?:app)?\.com|cdn\.discordapp\.com|pastebin\.com|webhook|raw\.githubusercontent\.com|bit\.ly|tinyurl\.com|ngrok|proton\.me)[^\s'\"<>]*",
        flags=re.I,
    ),
}

BENIGN_IDENTIFIER_REPLACEMENTS = {
    "base64": "codec",
    "b64encode": "encode_text",
    "b64decode": "decode_text",
    "urllib": "clientlib",
    "urllib2": "clientlib2",
    "requests": "webclient",
    "socket": "channel",
    "subprocess": "worker",
    "Popen": "start_task",
    "popen": "start_task",
    "system": "status",
    "eval": "compute",
    "exec": "run_block",
    "powershell": "shell_tool",
    "EncodedCommand": "encoded_arg",
    "encodedcommand": "encoded_arg",
}

BENIGN_DOTTED_REPLACEMENTS = {
    "os.system": "os.status",
}

BENIGN_STRING_REPLACEMENTS = {
    "invoke-webrequest": "retrieve_resource",
    "encodedcommand": "encoded_arg",
    "powershell": "shell_tool",
    "certutil": "cert_tool",
    "proton.me": "mail_service",
    "pastebin": "note_service",
    "discord": "chat_service",
    "webhook": "callback_endpoint",
    "cmd.exe": "cmd_tool",
    "curl": "fetcher",
    "wget": "downloader",
    "iex": "shell_expr",
}

INJECTION_VIEWS = {
    "inject_suspicious_placeholder": "# SUSPICIOUS_CUE_1",
    "inject_malicious_words": "# powershell encodedcommand subprocess base64 webhook",
    "inject_security_warning": "# suspicious malicious payload hidden backdoor",
    "inject_generic_mask": "# MASK MASK MASK",
    "inject_random_token": "# RANDOM_TOKEN RANDOM_TOKEN RANDOM_TOKEN",
}

ATTACK_COMMENT_POOL = [
    "# powershell encodedcommand subprocess base64 webhook",
    "# download payload and execute hidden command",
    "# reverse shell backdoor persistence",
    "# steal credentials and exfiltrate data",
    "# obfuscated malware loader using encoded command",
    "# suspicious payload dropper callback endpoint",
    "# hidden process launch with remote command",
]

ATTACK_KEYWORD_POOL = [
    "# powershell subprocess webhook",
    "# payload downloader backdoor",
    "# credential theft exfiltration",
    "# reverse-shell persistence malware",
    "# encodedcommand loader callback",
    "# dropper execution payload",
    "# command-and-control beacon",
]

NEGATIVE_COMMENT_POOL = [
    "# suspicious",
    "# malicious",
    "# dangerous",
    "# risky",
    "# harmful",
    "# untrusted",
    "# questionable",
]

BENIGN_SECURITY_COMMENTS = [
    "# educational malware analysis example",
    "# benign security research note",
    "# do not execute payload, documentation only",
]

CODE_IRRELEVANT_COMMENTS = [
    "# TODO: update documentation",
    "# helper function for package setup",
    "# standard configuration block",
]


def mask_terms(text: str, terms: Iterable[str], prefix: str) -> Tuple[str, Dict[str, str]]:
    mapping: Dict[str, str] = {}
    result = text
    for term in sorted(set(terms), key=len, reverse=True):
        pattern = re.compile(re.escape(term), flags=re.I)
        if not pattern.search(result):
            continue
        placeholder = f"{prefix}_{len(mapping) + 1}"
        mapping[placeholder] = term
        result = pattern.sub(placeholder, result)
    return result, mapping


def mask_patterns(text: str, patterns: Dict[str, re.Pattern], prefix: str, start_index: int = 0) -> Tuple[str, Dict[str, str]]:
    mapping: Dict[str, str] = {}
    result = text
    next_index = start_index + 1
    for cue_name, pattern in patterns.items():
        while True:
            match = pattern.search(result)
            if not match:
                break
            placeholder = f"{prefix}_{next_index}"
            mapping[placeholder] = cue_name
            result = result[:match.start()] + placeholder + result[match.end():]
            next_index += 1
    return result, mapping


def mask_suspicious(text: str) -> Tuple[str, Dict[str, str]]:
    masked, term_map = mask_terms(text, SUSPICIOUS_CUES, "SUSPICIOUS_CUE")
    masked, pattern_map = mask_patterns(masked, PATTERN_CUES, "SUSPICIOUS_CUE", len(term_map))
    return masked, {**term_map, **pattern_map}


def replace_suspicious_with_fixed_token(text: str, replacement: str) -> Tuple[str, Dict[str, str]]:
    mapping: Dict[str, str] = {}
    result = text

    for cue in sorted(set(SUSPICIOUS_CUES), key=len, reverse=True):
        pattern = re.compile(re.escape(cue), flags=re.I)
        result, count = pattern.subn(replacement, result)
        if count:
            mapping[cue] = replacement

    for cue_name, pattern in PATTERN_CUES.items():
        result, count = pattern.subn(replacement, result)
        if count:
            mapping[cue_name] = replacement

    return result, mapping


def mask_single_cue(text: str, cue: str) -> Tuple[str, Dict[str, str]]:
    if cue in PATTERN_CUES:
        return mask_patterns(text, {cue: PATTERN_CUES[cue]}, "SUSPICIOUS_CUE")
    return mask_terms(text, [cue], "SUSPICIOUS_CUE")


def replace_command_string_terms(text: str) -> Tuple[str, Dict[str, str]]:
    mapping: Dict[str, str] = {}
    result = text

    for original, benign in sorted(BENIGN_STRING_REPLACEMENTS.items(), key=lambda item: len(item[0]), reverse=True):
        pattern = re.compile(re.escape(original), flags=re.I)
        if pattern.search(result):
            mapping[original] = benign
            result = pattern.sub(benign, result)

    if PATTERN_CUES["long_base64"].search(result):
        mapping["long_base64"] = "sample_blob"
        result = PATTERN_CUES["long_base64"].sub("sample_blob", result)

    return result, mapping


def benign_replace_python_tokens(text: str) -> Tuple[str, Dict[str, str]]:
    mapping: Dict[str, str] = {}
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except tokenize.TokenError:
        replaced, string_map = replace_command_string_terms(text)
        return replaced, string_map

    output = []
    for tok in tokens:
        tok_type, tok_string, start, end, line = tok
        replacement = tok_string
        if tok_type == tokenize.NAME and tok_string in BENIGN_IDENTIFIER_REPLACEMENTS:
            replacement = BENIGN_IDENTIFIER_REPLACEMENTS[tok_string]
            mapping[tok_string] = replacement
        elif tok_type == tokenize.STRING:
            replacement, string_map = replace_command_string_terms(tok_string)
            mapping.update(string_map)
        output.append(tok._replace(string=replacement))

    replaced = tokenize.untokenize(output)
    return replaced, mapping


def benign_replacement(text: str) -> Tuple[str, Dict[str, str]]:
    replaced, mapping = benign_replace_python_tokens(text)
    for original, benign in BENIGN_DOTTED_REPLACEMENTS.items():
        if original in text or original in replaced:
            mapping[original] = benign
    return replaced, mapping


def inject_comment_after_imports(text: str, injected_text: str) -> str:
    lines = text.splitlines(keepends=True)
    insertion_line = 0

    try:
        module = ast.parse(text)
        body_index = 0
        if (
            module.body
            and isinstance(module.body[0], ast.Expr)
            and isinstance(module.body[0].value, ast.Constant)
            and isinstance(module.body[0].value.value, str)
        ):
            insertion_line = module.body[0].end_lineno or module.body[0].lineno
            body_index = 1

        while body_index < len(module.body):
            node = module.body[body_index]
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                break
            insertion_line = node.end_lineno or node.lineno
            body_index += 1
    except (SyntaxError, ValueError):
        insertion_line = 0

    comment_line = injected_text + "\n"
    return "".join(lines[:insertion_line]) + comment_line + "".join(lines[insertion_line:])


def stable_injection_seed(sample_id: str, view_name: str) -> int:
    digest = hashlib.sha256(f"{sample_id}{view_name}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=False)


def comment_insertion_candidates(text: str) -> List[int]:
    lines = text.splitlines(keepends=True)
    end_position = len(lines)
    while end_position > 0 and not lines[end_position - 1].strip():
        end_position -= 1
    candidates = {max(0, end_position - 1)}

    try:
        module = ast.parse(text)
    except (SyntaxError, ValueError):
        return [0]

    body_index = 0
    if (
        module.body
        and isinstance(module.body[0], ast.Expr)
        and isinstance(module.body[0].value, ast.Constant)
        and isinstance(module.body[0].value.value, str)
    ):
        body_index = 1

    import_end = None
    while body_index < len(module.body):
        node = module.body[body_index]
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            break
        import_end = node.end_lineno or node.lineno
        body_index += 1
    if import_end is not None:
        candidates.add(import_end)

    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            candidates.add(max(0, node.lineno - 1))
        elif (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and (
                (isinstance(node.value.func, ast.Name) and node.value.func.id == "setup")
                or (isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "setup")
            )
        ):
            candidates.add(max(0, node.lineno - 1))

    return sorted(position for position in candidates if 0 <= position <= len(lines))


def inject_random_comments(
    text: str,
    comments: List[str],
    sample_id: str,
    view_name: str,
) -> Tuple[str, Dict[str, object]]:
    seed = stable_injection_seed(sample_id, view_name)
    rng = random.Random(seed)
    candidates = comment_insertion_candidates(text)
    if not candidates:
        candidates = [0]

    placements: Dict[int, List[str]] = {}
    for comment in comments:
        position = rng.choice(candidates)
        placements.setdefault(position, []).append(comment)

    lines = text.splitlines(keepends=True)
    output: List[str] = []
    insertion_lines: List[int] = []
    for position in range(len(lines) + 1):
        if position in placements:
            indentation = ""
            if position < len(lines):
                indentation = re.match(r"[ \t]*", lines[position]).group(0)
            for comment in placements[position]:
                insertion_lines.append(len(output) + 1)
                output.append(f"{indentation}{comment}\n")
        if position < len(lines):
            output.append(lines[position])

    return "".join(output), {
        "injected_comments": comments,
        "insertion_lines": insertion_lines,
        "seed": seed,
    }


def extract_keywords(text: str) -> List[str]:
    found = []
    for cue in sorted(set(SUSPICIOUS_CUES), key=len, reverse=True):
        if re.search(re.escape(cue), text, flags=re.I):
            found.append(cue)
    for cue, pattern in PATTERN_CUES.items():
        if pattern.search(text):
            found.append(cue)
    return found


def keyword_view_name(cue: str) -> str:
    return "mask_keyword__" + re.sub(r"[^A-Za-z0-9]+", "_", cue).strip("_").lower()


def base_fields(row: dict) -> dict:
    return {
        "sample_id": row["sample_id"],
        "package_name": row.get("package_name", ""),
        "file_source": row.get("file_source", ""),
        "ecosystem": "pypi",
        "language": row.get("language", ""),
        "label": int(row["label"]),
        "source": row.get("source", ""),
        "content_hash": row.get("content_hash", ""),
    }


def make_views(row: dict, include_behavior: bool, include_keyword_contribution: bool) -> List[dict]:
    content = str(row.get("content", ""))
    base = base_fields(row)

    suspicious, suspicious_map = mask_suspicious(content)
    generic, generic_map = replace_suspicious_with_fixed_token(content, "MASK")
    random_masked, random_map = replace_suspicious_with_fixed_token(content, "RANDOM_TOKEN")
    deleted, delete_map = replace_suspicious_with_fixed_token(content, "")
    benign, benign_map = benign_replacement(content)
    keywords = extract_keywords(content)
    keywords_content = "\n".join(f"- {kw}" for kw in keywords) if keywords else "(no listed cues found)"

    views = [
        {**base, "view": "original", "view_content": content, "metadata": {}},
        {**base, "view": "mask_suspicious_cues", "view_content": suspicious, "metadata": suspicious_map},
        {**base, "view": "mask_generic", "view_content": generic, "metadata": generic_map},
        {**base, "view": "mask_random", "view_content": random_masked, "metadata": random_map},
        {**base, "view": "mask_delete", "view_content": deleted, "metadata": delete_map},
        {**base, "view": "benign_replacement", "view_content": benign, "metadata": benign_map},
        {**base, "view": "keywords_only", "view_content": keywords_content, "metadata": {"keywords": keywords}},
    ]

    for view_name, injected_text in INJECTION_VIEWS.items():
        views.append({
            **base,
            "view": view_name,
            "view_content": inject_comment_after_imports(content, injected_text),
            "metadata": {"injected_text": injected_text},
        })

    random_comment_specs = [
        ("inject_comment_attack_words_1", 1),
        ("inject_comment_attack_words_2", 2),
        ("inject_comment_attack_words_3", 3),
        ("inject_comment_attack_words_4", 4),
        ("inject_comment_attack_words_5", 5),
    ]
    for view_name, count in random_comment_specs:
        seed = stable_injection_seed(str(row["sample_id"]), view_name)
        comments = random.Random(seed).sample(ATTACK_COMMENT_POOL, k=count)
        injected_content, injection_metadata = inject_random_comments(
            content,
            comments,
            str(row["sample_id"]),
            view_name,
        )
        views.append({
            **base,
            "view": view_name,
            "view_content": injected_content,
            "metadata": injection_metadata,
        })

    attack_keyword_specs = [
        ("inject_comment_attack_keywords_1", 1),
        ("inject_comment_attack_keywords_2", 2),
        ("inject_comment_attack_keywords_3", 3),
        ("inject_comment_attack_keywords_4", 4),
        ("inject_comment_attack_keywords_5", 5),
    ]
    for view_name, count in attack_keyword_specs:
        seed = stable_injection_seed(str(row["sample_id"]), view_name)
        comments = random.Random(seed).sample(ATTACK_KEYWORD_POOL, k=count)
        injected_content, injection_metadata = inject_random_comments(
            content,
            comments,
            str(row["sample_id"]),
            view_name,
        )
        views.append({
            **base,
            "view": view_name,
            "view_content": injected_content,
            "metadata": injection_metadata,
        })

    negative_comment_specs = [
        ("inject_comment_negative_words_1", 1),
        ("inject_comment_negative_words_2", 2),
        ("inject_comment_negative_words_3", 3),
        ("inject_comment_negative_words_4", 4),
        ("inject_comment_negative_words_5", 5),
    ]
    for view_name, count in negative_comment_specs:
        seed = stable_injection_seed(str(row["sample_id"]), view_name)
        comments = random.Random(seed).sample(NEGATIVE_COMMENT_POOL, k=count)
        injected_content, injection_metadata = inject_random_comments(
            content,
            comments,
            str(row["sample_id"]),
            view_name,
        )
        views.append({
            **base,
            "view": view_name,
            "view_content": injected_content,
            "metadata": injection_metadata,
        })

    for view_name, comments in [
        ("inject_comment_benign_security_context", BENIGN_SECURITY_COMMENTS),
        ("inject_comment_code_irrelevant", CODE_IRRELEVANT_COMMENTS),
    ]:
        injected_content, injection_metadata = inject_random_comments(
            content,
            comments,
            str(row["sample_id"]),
            view_name,
        )
        views.append({
            **base,
            "view": view_name,
            "view_content": injected_content,
            "metadata": injection_metadata,
        })

    if include_behavior:
        behavior, behavior_map = mask_terms(content, BEHAVIOR_CUES, "BEHAVIOR_CUE")
        views.append({**base, "view": "mask_behavior_cues", "view_content": behavior, "metadata": behavior_map})

    if include_keyword_contribution:
        for cue in keywords:
            masked, mapping = mask_single_cue(content, cue)
            if mapping:
                views.append({
                    **base,
                    "view": keyword_view_name(cue),
                    "view_content": masked,
                    "metadata": {"keyword": cue, "mask_map": mapping},
                })

    return views


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="data/sample_manifest.csv")
    parser.add_argument("--output", default="data/ablation_views.jsonl")
    parser.add_argument("--include-behavior-cues", action="store_true")
    parser.add_argument("--include-keyword-contribution", action="store_true")
    parser.add_argument("--log", default="logs/build_ablation_views.log")
    args = parser.parse_args()

    setup_logging(args.log)
    df = pd.read_csv(args.manifest).fillna("")
    done = load_done_keys(args.output, ["sample_id", "view"])
    wrote = 0
    for _, row in df.iterrows():
        try:
            for view in make_views(row.to_dict(), args.include_behavior_cues, args.include_keyword_contribution):
                key = (view["sample_id"], view["view"])
                if key in done:
                    continue
                append_jsonl(args.output, view)
                wrote += 1
        except Exception as exc:
            logging.exception("Failed sample_id=%s: %s", row.get("sample_id"), exc)
    logging.info("Wrote %s new views to %s", wrote, args.output)


if __name__ == "__main__":
    main()
