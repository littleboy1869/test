"""Solvers for the TryScrapeMe practice challenges (https://tryscrapeme.com/challenges).

Each solver fetches its challenge live and returns the answer string to paste
into the challenge's "Verify" box (the site requires you to be logged in to
submit, so submission is left to you).

    python solve.py              # run every challenge
    python solve.py sprites abc  # run only the named ones
    python solve.py --list       # list challenge names
"""
import argparse
import base64
import hashlib
import json
import random
import re
import string
import sys
import time
from difflib import SequenceMatcher
from io import BytesIO
from urllib.parse import urljoin, urlsplit

import pytesseract
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from lxml import etree
from PIL import Image, ImageOps

import captcha_ocr

BASE = "https://tryscrapeme.com"
PRACTICE = f"{BASE}/web-scraping-practice"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

SOLVERS = {}


def challenge(name):
    def register(fn):
        SOLVERS[name] = fn
        return fn
    return register


def session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = UA
    return s


def fresh(url: str) -> str:
    """Append a cache-busting parameter; Cloudflare caches some pages (and stale captcha ids)."""
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}_={random.random()}"


def html(s: requests.Session, url: str, **kw):
    r = s.get(url, **kw)
    r.raise_for_status()
    return etree.HTML(r.text)


def money(values) -> list[float]:
    """Parse price strings such as '$10.49' or ' 7.6 ' into floats, skipping blanks."""
    out = []
    for v in values:
        v = re.sub(r"[^\d.]", "", v or "")
        if v:
            out.append(float(v))
    return out


def fmt(x: float) -> str:
    return f"{x:.2f}"


def table_prices(root) -> list[float]:
    """Prices from the 4th column of every body row, using the full text of the cell."""
    return money("".join(td.xpath(".//text()")) for td in root.xpath("//tbody/tr/td[4]"))


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


# --- beginner --------------------------------------------------------------

@challenge("abc")
def abc(s):
    return fmt(sum(table_prices(html(s, f"{PRACTICE}/beginner/abc"))))


@challenge("parse")
def parse(s):
    return fmt(sum(table_prices(html(s, f"{PRACTICE}/beginner/parse"))))


@challenge("user-agent")
def user_agent(s):
    prices = table_prices(html(s, f"{PRACTICE}/beginner/user-agent"))
    return fmt(sum(prices) / len(prices))


@challenge("images")
def images(s):
    url = f"{PRACTICE}/beginner/images"
    target = "gzybck.jpg"
    for src in html(s, url).xpath("//img/@src"):
        if src.split("?")[0].endswith("/" + target):
            return md5(s.get(urljoin(url, src)).content)
    raise RuntimeError(f"{target} not found on page")


def crawl_pages(s, page_url):
    """Follow every ?pageno= link from the challenge page, summing table prices per page.

    Only the query string of each link is used: the Pagination challenge's links point at
    /pagination?pageno=N, which 404s, while the same query on the challenge URL works.
    """
    seen, prices = set(), []
    queue = [urlsplit(href).query for href in html(s, page_url).xpath("//li/a/@href")]
    while queue:
        query = queue.pop(0)
        if "pageno=" not in query or query in seen:
            continue
        seen.add(query)
        root = html(s, f"{page_url}?{query}")
        prices += table_prices(root)
        queue += [urlsplit(href).query for href in root.xpath("//li/a/@href")]
    return prices


@challenge("pagination")
def pagination(s):
    return fmt(sum(crawl_pages(s, f"{PRACTICE}/beginner/pagination")))


@challenge("opaque-pagination")
def opaque_pagination(s):
    return fmt(sum(crawl_pages(s, f"{PRACTICE}/beginner/opaque-pagination")))


@challenge("iframe")
def iframe(s):
    url = f"{PRACTICE}/beginner/iframe"
    src = html(s, url).xpath("//iframe/@src")[0]
    prices = table_prices(html(s, urljoin(url, src)))
    return fmt(sum(prices) / len(prices))


@challenge("post")
def post(s):
    url = f"{PRACTICE}/beginner/post"
    form = html(s, url).xpath("//form[@name='frm']")[0]
    data = {i.get("name"): i.get("value", "") for i in form.xpath(".//input[@name]")}
    r = s.post(urljoin(url, form.get("action")), data=data)
    r.raise_for_status()
    return fmt(sum(table_prices(etree.HTML(r.text))))


@challenge("ajax")
def ajax(s):
    rows = s.get(f"{PRACTICE}/beginner/ajax/api").json()
    return fmt(sum(money(str(r["price"]) for r in rows)))


@challenge("simulate-login")
def simulate_login(s):
    url = f"{PRACTICE}/beginner/simulate-login"
    form = html(s, url).xpath("//form")[-1]
    data = {i.get("name"): i.get("value", "") for i in form.xpath(".//input[@name]")}
    r = s.post(urljoin(url, form.get("action")), data=data)
    r.raise_for_status()
    prices = table_prices(etree.HTML(r.text))
    if not prices:
        raise RuntimeError("login did not return the data table")
    return fmt(sum(prices))


def ocr_match(image: Image.Image, title: str) -> float:
    """How well OCR text from a cover image matches the given title (0..1)."""
    gray = image.convert("L")
    gray = gray.resize((gray.width * 3, gray.height * 3), Image.LANCZOS)
    text = ""
    for img in (gray, ImageOps.invert(gray)):
        text += " " + pytesseract.image_to_string(img, config="--psm 11")
    text = re.sub(r"[^a-z]", "", text.lower())
    want = re.sub(r"[^a-z]", "", title.lower())
    best = 0.0
    for i in range(max(1, len(text) - len(want) + 1)):
        best = max(best, SequenceMatcher(None, want, text[i:i + len(want)]).ratio())
    return best


@challenge("base64")
def base64_images(s):
    title = "Night Tiger"
    blobs = [base64.b64decode(b) for b in
             html(s, f"{PRACTICE}/beginner/base64").xpath("//img/@src")
             for b in re.findall(r"^data:image/\w+;base64,(.+)$", b)]
    scores = [ocr_match(Image.open(BytesIO(b)), title) for b in blobs]
    return md5(blobs[scores.index(max(scores))])


@challenge("form")
def form(s):
    value = html(s, f"{PRACTICE}/beginner/form").xpath("//input[@type='hidden']/@value")[0]
    return md5(value.encode())


@challenge("random")
def random_classes(s):
    # Class names change on every request, so select by structure instead:
    # each book is a <div> holding an <h2> title followed by author and price <div>s.
    root = html(s, fresh(f"{PRACTICE}/beginner/random"))
    prices = money(root.xpath("//div[h2]/div[last()]/text()"))
    return fmt(sum(prices))


# --- intermediate ----------------------------------------------------------

@challenge("verification-code")
def verification_code(s, attempts=40):
    url = f"{PRACTICE}/intermediate/verification-code"
    for _ in range(attempts):
        s.cookies.clear()
        root = html(s, fresh(url))
        form = root.xpath("//form")[-1]
        data = {i.get("name"): i.get("value", "") for i in form.xpath(".//input[@name]")}
        png = s.get(urljoin(url, form.xpath(".//img/@src")[0])).content
        code = captcha_ocr.solve(png)
        if not code:
            continue
        data["vcode"] = code
        r = s.post(urljoin(url, form.get("action")), data=data, allow_redirects=False)
        location = urljoin(url, r.headers.get("location", ""))
        if r.status_code in (301, 302, 303) and location.split("?")[0] != url:
            prices = table_prices(html(s, location))
            if prices:
                return fmt(sum(prices))
    raise RuntimeError(f"captcha not solved in {attempts} attempts")


@challenge("pseudo")
def pseudo(s):
    # The <span> prices are display:none decoys; the visible price is CSS ::after content.
    r = s.get(f"{PRACTICE}/intermediate/pseudo")
    shown = {int(n): v for n, v in
             re.findall(r"tr:nth-child\((\d+)\)\s*td\.price::after\s*\{\s*content:\s*\"([^\"]*)\"", r.text)}
    rows = len(etree.HTML(r.text).xpath("//table[contains(@class,'books')]/tbody/tr"))
    return fmt(sum(money(shown.get(i, "") for i in range(1, rows + 1))))


@challenge("sprites")
def sprites(s):
    r = s.get(f"{PRACTICE}/intermediate/sprites")
    sheet_b64 = re.search(r"\.sprite\s*\{[^}]*base64,([^'\")]+)", r.text).group(1)
    sheet = Image.open(BytesIO(base64.b64decode(sheet_b64))).convert("RGBA")
    flat = Image.new("RGBA", sheet.size, "white")
    flat.alpha_composite(sheet)
    gray = flat.convert("L")
    width = int(re.search(r"\.sprite\s*\{[^}]*width:\s*(\d+)px", r.text).group(1))

    glyph = {}
    for cls, pos in re.findall(r"\.(\w+)\s*\{\s*background-position:\s*(-?\d+)px", r.text):
        x = -int(pos)
        crop = gray.crop((x, 0, x + width, gray.height))
        crop = ImageOps.expand(crop.resize((width * 6, gray.height * 6), Image.LANCZOS), 30, 255)
        ch = pytesseract.image_to_string(
            crop, config="--psm 10 -c tessedit_char_whitelist=0123456789.").strip()
        glyph[cls] = ch if ch else "."  # the decimal point is too small for Tesseract

    prices = []
    for td in etree.HTML(r.text).xpath("//tbody/tr/td[4]"):
        text = ""
        for span in td.xpath(".//span[contains(@class,'sprite')]"):
            text += "".join(glyph.get(c, "") for c in span.get("class").split() if c != "sprite")
        prices += money([text])
    return fmt(sum(prices) / len(prices))


@challenge("offset")
def offset(s):
    # Digits are shuffled in the HTML and put back in order with position:relative offsets.
    r = s.get(f"{PRACTICE}/intermediate/offset")
    width = int(re.search(r"\.digit\s*\{[^}]*width:\s*(\d+)px", r.text).group(1))
    shift = {cls: int(px) for cls, px in
             re.findall(r"\.digit\.(\w+)\s*\{\s*left:\s*(-?\d+)px", r.text)}
    prices = []
    for td in etree.HTML(r.text).xpath("//tbody/tr/td[4]"):
        placed = []
        spans = td.xpath("./span")
        for i, span in enumerate(spans):
            classes = (span.get("class") or "").split()
            if "digit" in classes:
                x = i * width + sum(shift.get(c, 0) for c in classes)
                placed.append((x, span.text))
            else:
                placed.append((10_000 + i, span.text))  # unshifted tail such as ".61"
        prices += money(["".join(t for _, t in sorted(placed))])
    return fmt(sum(prices) / len(prices))


@challenge("timestamp-signature")
def timestamp_signature(s):
    # Reverse-engineered from timestamp_signature.min.js:
    #   t = unix seconds, n = 16 random [A-Za-z0-9], s = md5(t + n)
    t = str(int(time.time()))
    n = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    rows = s.get(f"{PRACTICE}/intermediate/timestamp-signature/api",
                 params={"t": t, "n": n, "s": md5((t + n).encode())}).json()
    return fmt(sum(float(r["price"]) for r in rows if float(r["stars"]) > 4))


def aes_ecb_decrypt(b64_ciphertext: str, key: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(b64_ciphertext)), 16)


@challenge("anti-selenium")
def anti_selenium(s):
    # Reverse-engineered from anti_selenium.min.js. The page only serves real data to
    # browsers without automation markers; plain HTTP has none, so we replay its calls:
    #   1. GET anti-selenium/data?t=<ms>    -> header secret-token; key = token[:32]
    #   2. GET anti-selenium/api?key=<key>  -> body; AES key = body[160:192],
    #      ciphertext (base64, AES-ECB, PKCS7) = body without that slice.
    api = f"{PRACTICE}/intermediate/anti-selenium"
    s.get(api)
    r = s.get(f"{api}/data", params={"t": int(time.time() * 1000)})
    key = r.headers["secret-token"][:32]
    body = s.get(f"{api}/api", params={"key": key}).text
    rows = json.loads(aes_ecb_decrypt(body[:160] + body[192:], body[160:192].encode()))
    return fmt(sum(float(r["price"]) for r in rows))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*", help="challenges to run (default: all)")
    ap.add_argument("--list", action="store_true", help="list challenge names")
    args = ap.parse_args()
    if args.list:
        print("\n".join(SOLVERS))
        return 0
    unknown = [n for n in args.names if n not in SOLVERS]
    if unknown:
        ap.error(f"unknown challenge(s): {', '.join(unknown)}")
    failed = 0
    for name in args.names or SOLVERS:
        try:
            answer = SOLVERS[name](session())
        except Exception as e:  # keep going so one broken challenge doesn't hide the rest
            failed += 1
            answer = f"ERROR: {e!r}"
        print(f"{name:20} {answer}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
