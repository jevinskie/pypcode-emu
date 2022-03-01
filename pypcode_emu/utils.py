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
