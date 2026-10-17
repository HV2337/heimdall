"""Laptop-only downloader for licensed Hugging Face threat datasets."""

from __future__ import annotations

import json
import platform
import re
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "eval" / "data" / "external"
DATASETS = (
    ("deepset/prompt-injections", "deepset_prompt_injections"),
    ("Lakera/gandalf_ignore_instructions", "lakera_gandalf_ignore_instructions"),
    ("jackhhao/jailbreak-classification", "jackhhao_jailbreak_classification"),
)
_ENGLISH_WORDS = frozenset(
    "a about after all an and any are as at be been before between but by can could did do does for from had has have he her here hers him his how i if in into is it its may me might more most my no not of on one or our out over please should so some such than that the their them then there these they this through to up us very was we were what when where which who will with would you your patient clinical medical care record prompt message system instructions blood pressure dose data".split()
)


def is_english(text: str) -> bool:
    """Keep English-like rows: mostly Latin letters plus at least one common word.

    This conservative, dependency-free heuristic is documented in the adjacent
    README; it is not a general-purpose language identification model.
    """
    letters = [char for char in text if char.isalpha()]
    if not letters or sum(char.isascii() for char in letters) / len(letters) < 0.90:
        return False
    words = re.findall(r"[a-z]+", text.lower())
    return bool(words) and any(word in _ENGLISH_WORDS for word in words)


def _card_license(repo_id: str) -> tuple[str | None, str]:
    from huggingface_hub import hf_hub_download
    import yaml

    card_path = Path(hf_hub_download(repo_id=repo_id, repo_type="dataset", filename="README.md"))
    content = card_path.read_text(encoding="utf-8")
    if not content.startswith("---"):
        return None, "dataset card has no YAML metadata"
    parts = content.split("---", 2)
    if len(parts) < 3:
        return None, "malformed dataset-card metadata"
    metadata = yaml.safe_load(parts[1])
    if not isinstance(metadata, Mapping):
        return None, "dataset-card metadata is not a mapping"
    declared: set[str] = set()
    for value in (metadata.get("license"),
                  (metadata.get("dataset_info") or {}).get("license")
                  if isinstance(metadata.get("dataset_info"), Mapping) else None):
        if isinstance(value, str) and value.strip():
            declared.add(value.strip())
    if not declared:
        return None, "license metadata is missing"
    shown = ", ".join(sorted(declared))
    if len(declared) != 1:
        return None, f"conflicting license metadata: {shown}"
    license_name = next(iter(declared))
    allowed = {"mit", "apache-2.0", "cc-by-4.0"}
    if license_name.lower() not in allowed:
        return None, f"license is not in the approved set: {license_name}"
    return license_name, shown


def _text_and_label(row: Mapping[str, object], source: str) -> tuple[str, int] | None:
    text: object = None
    for field in ("text", "prompt", "instruction", "question"):
        if isinstance(row.get(field), str):
            text = row[field]
            break
    if not isinstance(text, str) or not text.strip():
        return None
    label: object = row.get("label", row.get("type", row.get("class", row.get("target"))))
    if source == "Lakera/gandalf_ignore_instructions":
        return text.strip(), 1
    if isinstance(label, str):
        normalized = label.strip().lower()
        if normalized in {"jailbreak", "injection", "malicious", "attack", "1"}:
            return text.strip(), 1
        if normalized in {"benign", "safe", "normal", "0"}:
            return text.strip(), 0
        return None
    if type(label) is int and label in (0, 1):
        return text.strip(), label
    return None


def main() -> None:
    if platform.machine().lower() == "s390x":
        raise SystemExit("This downloader is for laptop use only; do not run it on LinuxONE.")
    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise SystemExit("Install the laptop requirements first (datasets is required).") from exc

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for _, file_stub in DATASETS:
        for split_name in ("train", "validation", "test"):
            (OUTPUT_DIR / f"{file_stub}_{split_name}.jsonl").unlink(missing_ok=True)
    seen_across_datasets: set[str] = set()
    for repo_id, file_stub in DATASETS:
        try:
            license_name, license_message = _card_license(repo_id)
        except Exception as exc:
            license_name, license_message = None, f"could not read dataset-card metadata ({type(exc).__name__})"
        print(f"{repo_id}: license metadata: {license_message}")
        if license_name is None:
            print(f"SKIP {repo_id}: {license_message}.")
            continue
        try:
            dataset = load_dataset(repo_id)
            if not isinstance(dataset, Mapping):
                raise ValueError("dataset has no named splits")
            counts: dict[str, int] = {}
            for split_name, split_rows in dataset.items():
                if split_name not in {"train", "validation", "test"}:
                    continue
                output_path = OUTPUT_DIR / f"{file_stub}_{split_name}.jsonl"
                kept: list[dict[str, object]] = []
                for row in split_rows:
                    parsed = _text_and_label(row, repo_id)
                    if parsed is None:
                        continue
                    text, label = parsed
                    normalized = " ".join(text.split())
                    dedup_key = normalized.casefold()
                    if not normalized or dedup_key in seen_across_datasets or not is_english(normalized):
                        continue
                    seen_across_datasets.add(dedup_key)
                    kept.append({
                        "text": normalized,
                        "label": label,
                        "source": repo_id,
                        "split": split_name,
                        "license": license_name,
                    })
                output_path.write_text(
                    "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in kept),
                    encoding="utf-8",
                )
                counts[split_name] = len(kept)
            print(f"Saved {repo_id}: {counts}")
        except Exception as exc:
            print(f"SKIP {repo_id}: download or processing failed ({type(exc).__name__}).")


if __name__ == "__main__":
    main()
