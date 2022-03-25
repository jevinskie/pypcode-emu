import re

import colorful as cf

from .numeric_colors import num_color

NUMBER_LIT_RE = re.compile("((0x[a-f0-9]+)((:\d+)|\[\d+\])?)")


def colorize_pcode_nums(pcode: str) -> str:
    def xfrm(m: re.Match) -> str:
        print(m.groups())
        nstr = m.group(2)
        suffix = m.group(3) if m.group(3) else ""
        if m.group(3) is not None and m.group(4) is None:
            return f"{cf.lawngreen}{nstr}{cf.reset}{suffix}"
        # address
        return f"{num_color(int(nstr, 0))}{nstr}{cf.reset}{suffix}"

    return NUMBER_LIT_RE.sub(xfrm, pcode)
