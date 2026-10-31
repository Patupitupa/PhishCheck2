"""
security.py - small, framework-free security helpers for the PhishCheck app.

  RateLimiter    sliding-window limiter (used per session and once globally)
  load_qr_image  checks an uploaded image (size, real image format, dimensions)
                 and returns it as an array, so nothing is written to disk
"""
import time
import threading
from collections import deque
from io import BytesIO

import numpy as np
from PIL import Image

MAX_UPLOAD_BYTES = 2 * 1024 * 1024        # 2 MB
MAX_IMAGE_SIDE = 4000                     # pixels, width and height
ALLOWED_FORMATS = {"PNG", "JPEG"}         # decided by the file's content, not its name


class RateLimiter:
    """Allow at most `max_calls` calls in any `period` seconds."""

    def __init__(self, max_calls, period):
        self.max_calls = max_calls
        self.period = period
        self._calls = deque()
        self._lock = threading.Lock()

    def hit(self, now=None):
        """Record a call if allowed. Returns (allowed, seconds_to_wait)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._calls
            while q and now - q[0] >= self.period:
                q.popleft()
            if len(q) >= self.max_calls:
                return False, self.period - (now - q[0])
            q.append(now)
            return True, 0.0


def load_qr_image(data):
    """Returns (BGR numpy array, None) on success or (None, error message)."""
    if not data:
        return None, "The file is empty."
    if len(data) > MAX_UPLOAD_BYTES:
        return None, "The image is too large (max 2 MB)."
    try:
        with Image.open(BytesIO(data)) as im:           # reads the header only
            if im.format not in ALLOWED_FORMATS:
                return None, "Only PNG and JPG images are supported."
            width, height = im.size
            if width > MAX_IMAGE_SIDE or height > MAX_IMAGE_SIDE:
                return None, f"The image is too large (max {MAX_IMAGE_SIDE}x{MAX_IMAGE_SIDE} pixels)."
        with Image.open(BytesIO(data)) as im:
            im.load()                                    # fully decodes; fails on a corrupt file
            rgb = im.convert("RGB")
        return np.ascontiguousarray(np.array(rgb)[:, :, ::-1]), None
    except Exception:
        return None, "That file could not be read as an image."
