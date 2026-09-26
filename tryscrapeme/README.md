# TryScrapeMe solvers

Scrapers for every challenge on [tryscrapeme.com](https://tryscrapeme.com/challenges), a
practice range for web scraping. Each one fetches its challenge live and prints the answer
to paste into that challenge's **Verify** box (submitting requires being logged in on the
site, so that step is manual).

## Setup

```sh
sudo apt-get install -y tesseract-ocr
pip install -r requirements.txt
```

## Run

```sh
python solve.py              # all challenges
python solve.py sprites abc  # just these
python solve.py --list
```

## How the harder ones work

| Challenge | Trick |
| --- | --- |
| verification-code | OCR on the captcha (`captcha_ocr.py`): keep the digit colour, close the dotted strokes, strip the strike-through line, vote across Tesseract runs. About 1 in 5 reads is right, so it retries with fresh captchas until login succeeds. The captcha page is cache-busted because Cloudflare serves a stale captcha id. |
| base64 | Decodes the inline images and OCRs each cover to find the one titled "Night Tiger". |
| sprites | Cuts each glyph out of the CSS sprite sheet at its `background-position` and OCRs it. |
| offset | Rebuilds each price from the digits' CSS `left` offsets. |
| pseudo | Uses the prices from the CSS `::after` rules; the ones in the HTML are hidden decoys. |
| random | Selects rows by structure, since class names change on every request. |
| pagination | The page links point at `/pagination`, which 404s; the same query on the challenge URL works. |
| timestamp-signature | `s = md5(t + n)` with `t` = unix seconds and `n` = 16 random alphanumerics. |
| anti-selenium | Replays the page's calls: the `secret-token` header gives the key, and the API body is AES-ECB with its key embedded at characters 160–192. |

## Self-hosted Firecrawl (optional)

The solvers don't need it, but `firecrawl-local.sh` runs self-hosted Firecrawl inside a
Claude Code cloud session. Containers there have no internet access, so the script copies
the prebuilt apps out of the official images and runs them (plus Redis, RabbitMQ and
Postgres) as plain processes that go through the session's proxy.

```sh
./firecrawl-local.sh setup   # once per container
./firecrawl-local.sh start   # API on http://localhost:3002
firecrawl --api-url http://localhost:3002 --api-key local scrape <url>
```

It renders JavaScript pages (e.g. the AJAX challenge), but it can't do the captcha login,
signature or decryption challenges; `solve.py` handles those.
