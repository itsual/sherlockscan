"""Bounded literal decoding. Decoded content is never evaluated or imported."""

from __future__ import annotations

import base64
import binascii
import re
import zlib


def decode_literal(value: str | bytes, *, max_bytes=65536, max_depth=2):
    raw = value.encode() if isinstance(value, str) else value
    if len(raw) > max_bytes:
        return [], True
    results = []
    chain = []
    consumed = len(raw)
    for _ in range(max_depth):
        stripped = raw.strip()
        decoded = None
        encoding = None
        try:
            if re.fullmatch(rb"[a-fA-F0-9]{8,}", stripped) and len(stripped) % 2 == 0:
                decoded, encoding = binascii.unhexlify(stripped), "hex"
            elif re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", stripped) and len(stripped) >= 8:
                decoded, encoding = base64.b64decode(stripped, validate=True), "base64"
            elif raw.startswith((b"x\x01", b"x\x9c", b"x\xda")):
                obj = zlib.decompressobj()
                decoded = obj.decompress(raw, max_bytes + 1)
                if len(decoded) > max_bytes or obj.unconsumed_tail:
                    return results, True
                if not obj.eof:
                    return results, True
                encoding = "zlib"
        except (ValueError, binascii.Error, zlib.error):
            break
        if decoded is None:
            break
        consumed += len(decoded)
        if consumed > max_bytes:
            return results, True
        chain.append(encoding)
        # Match the entire bounded payload, not only its display preview.
        results.append((list(chain), decoded))
        raw = decoded
    return results, False
