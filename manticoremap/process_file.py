#! /usr/bin/env python

import yaml
import argparse
import os
from .fancy_parser import parse_line
from .versioned_file import versioned_write

unsupported = {'ioperm', 'arch_prctl', 'modify_ldt', 'execve'}
yaml.add_representer(int, lambda dumper, data: dumper.represent_int(hex(data)))

def process_lines(lines, verbose=0):
    out = []
    for line in lines:
        line = line.strip()
        if not len(line) or line.startswith('+++'):
            continue
        data = parse_line(line, v=verbose)
        if data.name in unsupported:
            continue
        out.append(data)
        if verbose:
            print(str(data))

    return out

def dump_lines(filename, out):
    versioned_write(filename, yaml.dump([d.yaml_dict() for d in out], default_flow_style=False))

def main():
    parser = argparse.ArgumentParser(description='Parse a trace file into YAML')
    parser.add_argument('file', help="Trace file to target")
    parser.add_argument('--verbose', '-v', action='count', help="Output verbosity")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: Invalid file path: {args.file}")

    with open(args.file, 'r') as infile:
        data = process_lines(infile.readlines(), args.verbose)
    dump_lines(args.file + '.yaml', data)

if __name__ == '__main__':
    main()



