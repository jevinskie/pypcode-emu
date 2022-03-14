from nativetypes import *


def u(self):
    if self.v < 0:
        return nint((1 << self.b) + self.v, self.b, False)
    return nint(self.v, self.b, False)


nint.u = property(u)

del u
