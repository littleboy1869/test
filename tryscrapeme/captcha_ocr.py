"""OCR for the digit captchas on the TryScrapeMe "Verification Code" challenge.

The images are 240x80 PNGs: six digits drawn in one colour as dotted strokes,
plus random dots in other colours and a wavy strike-through line in the digit
colour. We keep only the dominant opaque colour (drops the dots), close the
dotted strokes, remove the thin line with a vertical opening, then ask
Tesseract for digits under several preprocessing settings and rank the answers
by how often they come up.
"""
from collections import Counter
from io import BytesIO

import cv2
import numpy as np
import pytesseract
from PIL import Image

WHITELIST = "-c tessedit_char_whitelist=0123456789"


def _digit_mask(png: bytes) -> np.ndarray:
    rgba = np.array(Image.open(BytesIO(png)).convert("RGBA"))
    opaque = rgba[:, :, 3] > 0
    colours = Counter(map(tuple, rgba[opaque][:, :3]))
    main = np.array(colours.most_common(1)[0][0], dtype=rgba.dtype)
    mask = opaque & np.all(rgba[:, :, :3] == main, axis=2)
    return mask.astype(np.uint8) * 255


def _variants(mask: np.ndarray):
    closed = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, np.ones((2, 2), np.uint8))
    for k in (3, 4, 5):
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (1, k))
        opened = cv2.morphologyEx(closed, cv2.MORPH_OPEN, kernel)
        for d in (1, 2):
            img = cv2.dilate(opened, np.ones((d, d), np.uint8))
            img = 255 - cv2.resize(img, None, fx=3, fy=3, interpolation=cv2.INTER_NEAREST)
            yield cv2.copyMakeBorder(img, 20, 20, 20, 20, cv2.BORDER_CONSTANT, value=255)


def candidates(png: bytes, length: int = 6) -> list[str]:
    """Return plausible readings, most likely first."""
    votes = Counter()
    for img in _variants(_digit_mask(png)):
        for psm in (7, 8, 13):
            text = pytesseract.image_to_string(img, config=f"--psm {psm} {WHITELIST}").strip()
            if len(text) == length and text.isdigit():
                votes[text] += 1
    return [text for text, _ in votes.most_common()]


def solve(png: bytes, length: int = 6) -> str | None:
    found = candidates(png, length)
    return found[0] if found else None
