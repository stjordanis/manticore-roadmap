from .config import args
from manticore.native import Manticore
from manticore.core.plugin import Plugin
from .process_trace import process_trace
from .process_target import process_lines, update_left_from_right, dump_lines
from .file_ratio import files_ratio
from base64 import b64encode

import subprocess
import os


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

        self.lines.append('%s(%s) = %s' % (name.replace('sys_', ''), args_s, ret_s))


def collect_manticore_trace():
    m = Manticore(args.filename, argv=args.args)
    m.verbosity(2)

    pluginInstance = loggerPlugin()

    m.register_plugin(pluginInstance)

    #TODO this line needs some sort of timeout
    print(" ", "Running Manticore...")
    m.run()

    # TODO save mtrace to versioned file
    return pluginInstance.lines, m.workspace


def collect_kernel_trace(workspace):

    print("Entering workspace")
    os.chdir(workspace)

    print(" ", "Cleaning old trace...")
    subprocess.Popen(['sudo', '/usr/bin/trace-cmd', 'reset']).wait()

    print(" ", "Recording kernel trace...")
    # TODO write workspace files for stdout and stderr
    tracer = subprocess.Popen(['sudo', '/usr/bin/trace-cmd', 'record', '-e', 'syscalls', '-F', args.abspath] + args.args,
                              stdin=subprocess.PIPE,
                              stdout=open('ktrace.stdout', 'w'),
                              stderr=open('ktrace.stderr', 'w'))
    tracer.communicate(input=open(args.stdin_file, 'rb').read())

    print(" ", "Generating report...")
    report = subprocess.Popen(['sudo',  '/usr/bin/trace-cmd', 'report'],
                              stdout=open('ktrace_report.stdout', 'w'),
                              stderr=open('ktrace_report.stderr', 'w')).wait()

    print(" ", "Processing trace report...")
    data = open('ktrace_report.stdout').readlines()
    return [repr(l) for l in process_trace(filter(lambda l: ':' in l, data))]


def yamlify(ktrace, mtrace):

    klines = process_lines(ktrace)
    mlines = process_lines(mtrace)

    dump_lines('ktrace.yaml', klines)
    dump_lines('mtrace.yaml', mlines)

    update_left_from_right(klines, mlines)

    dump_lines('processed_ktrace.yaml', klines)
    dump_lines('processed_mtrace.yaml', mlines)

    return klines, mlines

def main():

    print("Tracing Manticore behavior...")
    mtrace, workspace = collect_manticore_trace()
    print("Tracing kernel behavior...")
    ktrace = collect_kernel_trace(workspace)

    with open('ktrace', 'w') as kfile:
        for line in ktrace:
            kfile.write(line + '\n')
    with open('mtrace', 'w') as mfile:
        for line in mtrace:
            mfile.write(line + '\n')

    pktrace, pmtrace = yamlify(ktrace, mtrace)

    print(files_ratio('processed_ktrace.yaml', 'processed_mtrace.yaml'))


if __name__ == '__main__':
    main()
