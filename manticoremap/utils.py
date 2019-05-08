def unsigned_hexlify(i):
    if type(i) is int:
        if i < 0:
            return hex((1 << 64) + i)
        return hex(i)
    return i