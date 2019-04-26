#!/usr/bin/env python

import argparse
import os

from manticore.native import Manticore
from manticore.core.plugin import Plugin
from manticore.utils.log import disable_colors
disable_colors()

class concretePlugin(Plugin):

    def will_start_run_callback(self, state, *_args):
        state.cpu.emulate_until(0)

parser = argparse.ArgumentParser(description='Try out a binary')
parser.add_argument('file', help="ELF Binary to run")
parser.add_argument('--verbose', '-v', action='count', help="Output verbosity")
args = parser.parse_args()

if not os.path.exists(args.file):
    print(f"Error: Invalid file path: {args.file}")

m = Manticore(args.file)
m.verbosity(0 if not type(args.verbose) is int else args.verbose)
m.register_plugin(concretePlugin())

m.run()

