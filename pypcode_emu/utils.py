import shutil
import subprocess
import sys
from typing import Callable

from bidict import bidict


def first(iterable, default=None):
    for item in iterable:
        return item
    return default


def first_where(iterable, pred, default=None):
    return first((x for x in iterable if pred(x)), default=default)


def first_where_key_is(iterable, key, val, default=None):
    return first_where(iterable, lambda x: x[key] == val, default=default)


def first_where_attr_is(iterable, key, val, default=None):
    return first_where(iterable, lambda x: getattr(x, key) == val, default=default)


def run_cmd(*args, log: bool = False):
    args = (*args,)
    if log:
        print(f"run_cmd args: {args}", file=sys.stderr)
    r = subprocess.run(list(map(str, args)), capture_output=True)
    if r.returncode != 0:
        sys.stderr.buffer.write(r.stdout)
        sys.stderr.buffer.write(r.stderr)
        raise subprocess.CalledProcessError(r.returncode, args, r.stdout, r.stderr)
    try:
        r.out = r.stdout.decode()
    except UnicodeDecodeError:
        pass
    return r


def gen_cmd(bin_name: str) -> Callable:
    bin_path = shutil.which(bin_name)
    assert bin_path is not None
    return lambda *args, **kwargs: run_cmd(bin_path, *args, **kwargs)


class UniqueBiDict(bidict):
    def __getitem__(self, item):
        a = self._fwdm.get(item, None)
        b = self._invm.get(item, None)
        if a is None and b is None:
            raise KeyError(item)
        assert (a is None) ^ (b is None)
        return a if b is None else b
