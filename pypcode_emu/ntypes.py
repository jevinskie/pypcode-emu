from nativetypes import *


def as_u(self):
    if self.v < 0:
        return nint((1 << self.b) + self.v, self.b, False)
    return nint(self.v, self.b, False)


nint.as_u = property(as_u)


def as_s(self):
    if self.s:
        return self
    return nint(self.v, self.b, True)


nint.as_s = property(as_s)

del as_s
