from collections import defaultdict


class Histogram(defaultdict):
    def __init__(self):
        super().__init__(int)

    @staticmethod
    def block_str(percentage: float, width: int = 80):
        full_width = width * 8
        num_blk = int(percentage * full_width)
        full_blks = num_blk // 8
        partial_blks = num_blk % 8
        return "█" * full_blks + ("", "▏", "▎", "▍", "▌", "▋", "▊", "▉")[partial_blks]

    def ascii_histogram(self, width=80):
        res = ""
        total = sum(self.values())
        sorted_self = dict(sorted(self.items(), key=lambda i: i[1], reverse=True))
        max_num = list(sorted_self.values())[0]
        for i, mn in enumerate(sorted_self.items()):
            m, n = mn
            res += f"{i+1:3d}: {m:8s} {self.block_str(n / max_num, width=width)}\n"
        return res
