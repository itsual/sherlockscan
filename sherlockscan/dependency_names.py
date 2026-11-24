"""Conservative, opt-in dependency name comparison on local metadata."""

from importlib.resources import files
from packaging.utils import canonicalize_name


def _one_edit(left, right):
    if len(left) == len(right):
        positions = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
        if len(positions) == 1:
            return True
        if len(positions) == 2:
            first, second = positions
            return second == first + 1 and left[first] == right[second] and left[second] == right[first]
        return False
    if abs(len(left) - len(right)) != 1:
        return False
    short, long = sorted((left, right), key=len)
    offset = next((i for i, (a, b) in enumerate(zip(short, long)) if a != b), len(short))
    return short[offset:] == long[offset + 1 :]


def watchlist():
    entries = files("sherlockscan.config").joinpath("dependency_watchlist.txt").read_text(encoding="utf-8")
    return tuple(sorted({canonicalize_name(line.strip()) for line in entries.splitlines() if line.strip()}))


def similar_names(name, watched):
    name = canonicalize_name(name)
    if name in watched or len(name) < 4:
        return ()
    return tuple(candidate for candidate in watched if len(candidate) >= 4 and _one_edit(name, candidate))
