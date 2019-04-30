from .config import args
from manticore.native import Manticore
from manticore.core.plugin import Plugin
from manticore.utils.log import disable_colors
from tempfile import NamedTemporaryFile
from plumbum.cmd import rm
from .process_trace import process_trace
from .process_target import process_to_yaml
from .file_ratio import calc_ratio
from base64 import b64encode

import subprocess
import logging


def unsigned_hexlify(i):
    if type(i) is int:
        if i < 0:
            return hex((1 << 64) + i)
        return hex(i)
    return i


class loggerPlugin(Plugin):

    lines = []

    def will_start_run_callback(self, state, *_args):
        state.cpu.emulate_until(0)

    def did_execute_syscall_callback(self, state, name, argv, ret):
        args = []
        for arg in argv:
            arg_s = arg
            if state.cpu.memory.access_ok(arg, 'r') and name not in {'sys_mprotect', 'sys_mmap'}:
                try:
                    s = state.cpu.read_string(arg, 32)
                    arg_s = f'B64STR:{b64encode(s.rstrip().encode("utf-8")).decode("utf-8")}' if s else arg_s
                except:
                    pass
            args.append(arg_s)

        args_s = ', '.join(unsigned_hexlify(a) for a in args)

        ret_s = f'{unsigned_hexlify(ret)}'

        print('%s(%s) = %s' % (name, args_s, ret_s))
        self.lines.append('%s(%s) = %s' % (name, args_s, ret_s))


def collect_manticore_trace():
    m = Manticore(args.filename, argv=args.args)
    m.verbosity(1)

    pluginInstance = loggerPlugin()

    m.register_plugin(pluginInstance)

    #TODO this line needs some sort of timeout
    m.run()

    # TODO save mtrace to versioned file
    return pluginInstance.lines


def collect_kernel_trace():
    rm["-f"]("trace.dat*")

    subprocess.Popen(['sudo', '/usr/bin/trace-cmd', 'reset'])
    subprocess.Popen(['sudo', '/usr/bin/trace-cmd', 'record', '-e', 'syscalls', '-F', args.filename] + args.args)

    outf = NamedTemporaryFile()
    subprocess.Popen(['sudo',  '/usr/bin/trace-cmd', 'report'], stdout=outf, stderr=outf)

    # TODO recreate grepping
    return process_trace(outf.read())

def yamlify(ktrace, mtrace):

    return process_to_yaml(ktrace, mtrace)

def main():

    #TODO make these coroutines
    mtrace = collect_manticore_trace()
    ktrace = collect_kernel_trace()

    pktrace, pmtrace = yamlify(ktrace, mtrace)
    print(calc_ratio(pktrace, pmtrace))


if __name__ == '__main__':
    main()
