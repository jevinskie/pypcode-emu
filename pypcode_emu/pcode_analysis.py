from typing import Sequence

from pypcode import Translation


class Liveness:
    instrs: Sequence[Translation]

    def __init__(self, instrs: Sequence[Translation]):
        self.instrs = instrs
        self._run()

    def _run(self):
        pass
