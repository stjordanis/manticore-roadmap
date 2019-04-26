from .config import args
from manticore.native import Manticore
from manticore.core.plugin import Plugin
from manticore.utils.log import disable_colors
from tempfile import NamedTemporaryFile
from plumbum.cmd import rm
from .process_trace import process_trace

import subprocess
import logging

disable_colors()

tempfile = NamedTemporaryFile()
filehandler = logging.FileHandler(tempfile.name)
filehandler.setFormatter(logging.Formatter('%(message)s'))

logging.getLogger('manticore.platform.linux').addHandler(filehandler)

class loggerPlugin(Plugin):

    def will_start_run_callback(self, state, *_args):
        state.cpu.emulate_until(0)

    def did_execute_syscall_callback(self, _state, name, argv, ret):



def collect_manticore_trace():
    m = Manticore(args.filename, argv=args.args)

    @m.init
    def emulate(state):
        state.cpu.emulate_until(0)

    m.verbosity(2)

    #TODO this line needs some sort of timeout
    m.run()

    # TODO save mtrace to versioned file
    return tempfile.readlines()


def collect_kernel_trace():
    rm["-f"]("trace.dat*")

    subprocess.Popen(['sudo', '/usr/bin/trace-cmd', 'reset'])
    subprocess.Popen(['sudo', '/usr/bin/trace-cmd', 'record', '-e', 'syscalls', '-F', args.filename] + args.args)

    outf = NamedTemporaryFile()
    subprocess.Popen(['sudo',  '/usr/bin/trace-cmd', 'report'], stdout=outf, stderr=outf)

    return process_trace(outf.read())

def main():

    #TODO make these coroutines
    mtrace = collect_manticore_trace()
    ktrace = collect_kernel_trace()


if __name__ == '__main__':
    main()
