import colorsys
import hashlib
import sys

import numpy as np

HASH_MAX = (1 << sys.hash_info.width) - 1


def term_color_hsv(h: float, s: float, v: float) -> str:
    r, g, b = colorsys.hsv_to_rgb(h, s, v)
    r, g, b = int(r * 255), int(g * 255), int(b * 255)
    return f"\x1b[38;2;{r};{g};{b}m"


def num_color(n: int) -> str:
    if n == 0:
        # red
        return term_color_hsv(0, 1, 1)
    # MAX = (1 << 64) - 1
    # lcg = (6364136223846793005 * n + 1) & MAX
    # NP_MAX = (1 << 63) - 1
    # rng = np.random.default_rng(lcg)
    # scaled = rng.integers(0, NP_MAX, endpoint=True) / NP_MAX
    rand_bytes = hashlib.sha256(n.to_bytes(16, "little")).digest()
    scaled = int.from_bytes(rand_bytes, "little") / ((1 << (len(rand_bytes) * 8)) - 1)
    scaled = 0.1 + (scaled * 0.9)
    return term_color_hsv(scaled, 1, 1)
