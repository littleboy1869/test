"""Catalogue Hugging Face models that are abliterated, uncensored or made with Heretic.

Uses the public Hub API (no token needed) to list every public model whose name or
tags match, then writes one row per model grouped by what it generates. Only
metadata is collected; no model files are downloaded.

    python collect.py            # writes models.csv, models.json and prints a summary
"""
import csv
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

import requests

API = "https://huggingface.co/api/models"
TERMS = ["abliterated", "uncensored", "heretic"]
FIELDS = ["pipeline_tag", "library_name", "downloads", "likes", "tags", "createdAt", "lastModified"]
OUT = Path(__file__).parent

# pipeline_tag -> what the model produces
MODALITY = {
    "text-generation": "text", "text2text-generation": "text", "conversational": "text",
    "image-text-to-text": "multimodal", "any-to-any": "multimodal",
    "visual-question-answering": "multimodal", "video-text-to-text": "multimodal",
    "audio-text-to-text": "multimodal",
    "text-to-image": "image", "image-to-image": "image", "unconditional-image-generation": "image",
    "text-to-video": "video", "image-to-video": "video", "video-to-video": "video",
    "text-to-speech": "audio", "text-to-audio": "audio", "audio-to-audio": "audio",
    "automatic-speech-recognition": "audio",
    "text-to-3d": "3d", "image-to-3d": "3d",
}


def pages(params):
    """Yield every model from a paginated /api/models query (follows the Link header)."""
    url, first = API, True
    s = requests.Session()
    while url:
        r = s.get(url, params=params if first else None, timeout=60)
        if r.status_code == 429:  # rate limited: back off and retry the same page
            time.sleep(int(r.headers.get("Retry-After", 30)))
            continue
        r.raise_for_status()
        yield from r.json()
        first = False
        url = r.links.get("next", {}).get("url")
        time.sleep(0.5)  # be polite to the Hub


def matched_terms(model):
    text = model["id"].lower() + " " + " ".join(model.get("tags") or []).lower()
    return [t for t in TERMS if re.search(t, text)]


# Many uploads (quantizations, LoRAs, ComfyUI checkpoints) carry no pipeline_tag, so fall
# back to the library and to model-family names in the repo id.
VIDEO_NAMES = re.compile(r"(?<![a-z])(ltx|wan-?2|wan-video|hunyuan-?video|mochi|cogvideo|video)")
IMAGE_NAMES = re.compile(r"flux|sdxl|sd-?1\.5|sd-?3|stable-diffusion|qwen-image|z-image|"
                         r"illustrious|pony|hidream|chroma|lumina|diffusion")
TEXT_NAMES = re.compile(r"qwen|llama|gemma|glm|mistral|mixtral|deepseek|phi-?\d|gpt|hermes|"
                        r"kimi|minimax|olmo|granite|nemotron|falcon|yi-|command-r|seed-oss")


def modality(model):
    tag = model.get("pipeline_tag")
    name = model["id"].split("/")[-1].lower()  # repo name only; uploader names mislead
    lib = model.get("library_name") or ""
    if tag in MODALITY:
        return MODALITY[tag]
    if tag in ("image-text-to-video",):
        return "video"
    if tag in ("image-text-to-image",):
        return "image"
    if tag in ("image-to-text",):
        return "multimodal"
    if VIDEO_NAMES.search(name):
        return "video"
    if IMAGE_NAMES.search(name) or lib in ("diffusers", "diffusion-single-file", "comfyui"):
        return "image"
    if lib == "mlx-vlm" or re.search(r"-vl\b|-vl-|vision", name):
        return "multimodal"
    tags = set(model.get("tags") or [])
    if (TEXT_NAMES.search(name) or lib in ("mlx", "transformers", "peft", "vllm", "ninfer")
            or "gguf" in tags or "text-generation-inference" in tags):
        return "text"
    return "other"


def main():
    models = {}
    for term in TERMS:
        for how, params in (("search", {"search": term}), ("tag", {"filter": term})):
            n = 0
            for m in pages({**params, "limit": 1000, "expand[]": FIELDS}):
                models.setdefault(m["id"], m)
                n += 1
            print(f"{how:6} {term:12} {n:6} results", file=sys.stderr)

    rows = []
    for m in models.values():
        terms = matched_terms(m)
        if not terms:  # a search hit on something unrelated (e.g. only the author name)
            continue
        base = [t.split(":", 2)[-1] for t in m.get("tags") or [] if t.startswith("base_model:")
                and t.count(":") == 1]
        rows.append({
            "id": m["id"],
            "url": f"https://huggingface.co/{m['id']}",
            "modality": modality(m),
            "pipeline_tag": m.get("pipeline_tag") or "",
            "library": m.get("library_name") or "",
            "matched": ",".join(terms),
            "gguf": "gguf" in (m.get("tags") or []),
            "base_model": ";".join(base),
            "downloads_30d": m.get("downloads", 0),
            "likes": m.get("likes", 0),
            "created": (m.get("createdAt") or "")[:10],
            "last_modified": (m.get("lastModified") or "")[:10],
        })
    rows.sort(key=lambda r: (r["modality"], -r["downloads_30d"]))

    with open(OUT / "models.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    (OUT / "models.json").write_text(json.dumps(rows, indent=1))

    print(f"\n{len(rows)} models")
    for mod, n in Counter(r["modality"] for r in rows).most_common():
        print(f"  {mod:11} {n}")
    for term in TERMS:
        print(f"  matched {term:12} {sum(term in r['matched'] for r in rows)}")


if __name__ == "__main__":
    main()
