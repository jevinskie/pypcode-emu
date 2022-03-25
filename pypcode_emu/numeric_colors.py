import colorsys
import hashlib

import colorful as cf

cf.use_true_colors()
cf.update_palette(
    {
        "slateblue": "#6A5ACD",
        "palegreen": "#98FB98",
        "fuschia": "#FF00FF",
        "lawngreen": "#7CFC00",
    }
)


def term_color_hsv(h: float, s: float, v: float) -> str:
    r, g, b = colorsys.hsv_to_rgb(h, s, v)
    r, g, b = int(r * 255), int(g * 255), int(b * 255)
    return f"\x1b[38;2;{r};{g};{b}m"


def num_color(n: int) -> str:
    if n == 0:
        # red
        return term_color_hsv(0, 1, 1)
    rand_bytes = hashlib.sha256(n.to_bytes(16, "little")).digest()
    scaled = int.from_bytes(rand_bytes, "little") / ((1 << (len(rand_bytes) * 8)) - 1)
    scaled = 0.1 + (scaled * 0.8)
    return term_color_hsv(scaled, 1, 1)
