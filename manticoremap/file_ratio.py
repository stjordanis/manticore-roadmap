import argparse
import os
import difflib


def calc_ratio(left_lines, right_lines):
    return difflib.SequenceMatcher(a=left_lines,
                                   b=right_lines).ratio()


def ratio_lines(left, right):
    ratio = calc_ratio(left, right)

    print(target, "::", ratio)
    return ratio


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse a trace file into YAML')
    parser.add_argument('target_dir', help="Name of the file to parse traces for")
    parser.add_argument('--verbose', '-v', action='count', help="Output verbosity")
    args = parser.parse_args()

    if not os.path.exists(args.target_dir):
        print(f"Error: Invalid directory path: {args.target_dir}")

    target = os.path.basename(args.target_dir)

    with open(os.path.join(args.target_dir, 'processed', f'{target}.ktrace.yaml'), 'r') as kfile:
        klines = kfile.readlines()

    with open(os.path.join(args.target_dir, 'processed', f'{target}.mtrace.yaml'), 'r') as mfile:
        mlines = mfile.readlines()

    ratio_lines(klines, mlines)