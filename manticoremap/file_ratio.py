import difflib


def calc_ratio(left_lines, right_lines):
    return difflib.SequenceMatcher(a=left_lines,
                                   b=right_lines).ratio()


def files_ratio(fname1, fname2):
    with open(fname1, 'r') as kfile:
        left_lines = kfile.readlines()

    with open(fname2, 'r') as mfile:
        right_lines = mfile.readlines()

    return calc_ratio(left_lines, right_lines)
