# Abliterated / uncensored / Heretic models on Hugging Face

`collect.py` lists every public Hugging Face model whose name or tags contain
"abliterated", "uncensored" or "heretic", using the public Hub API (metadata only; no
model files are downloaded), and writes `models.csv` (plus `models.json` locally).

```sh
pip install requests
python collect.py
```

Columns: `id`, `url`, `modality` (text, multimodal, image, video, audio, 3d, other),
`pipeline_tag`, `library`, `matched` terms, `gguf`, `base_model`, `downloads_30d`, `likes`,
`created`, `last_modified`.

`modality` comes from the model's pipeline tag when it has one, otherwise from its library
and model-family names (LTX/Wan for video, FLUX/Qwen-Image for image, and so on). Uploads
that give no clue are left as `other`. Search hits that only match on the uploader's name are
dropped.

## Model cards

`fetch_cards.py` downloads each model's README (its model card) into `cards.jsonl.gz`, one
`{"id", "status", "card"}` object per line. It stays under the Hub's anonymous limit
(3000 requests per 5 minutes), waits out any rate limit it hits, and resumes where it left
off if re-run. A full run takes about 1.5–2 hours. The output isn't committed (too large).

```sh
python fetch_cards.py
```
