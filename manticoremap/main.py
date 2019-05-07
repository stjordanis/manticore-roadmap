from .config import args
from manticore.native import Manticore
from manticore.core.plugin import Plugin
from manticore.platforms.platform import SyscallNotImplemented
from manticore.utils.log import disable_colors
from manticore.platforms.linux_syscall_stubs import SyscallStubs
from .process_trace import process_trace
from .process_target import process_lines, update_left_from_right, dump_lines
from .file_ratio import files_ratio
from base64 import b64encode
from collections import Counter

import subprocess
import os
import wrapt
import threading
import queue


def is_unimplemented(f):
    return isinstance(f, wrapt.wrappers.BoundFunctionWrapper) and f._self_wrapper.__name__ == 'unimplemented'


stubs = set(f.__name__
            for f in set(getattr(SyscallStubs, n) for n in dir(SyscallStubs) if 'sys_' in n)
            if is_unimplemented(f))

disable_colors()


def unsigned_hexlify(i):
    if type(i) is int:
        if i < 0:
            return hex((1 << 64) + i)
        return hex(i)
    return i


class TracerPlugin(Plugin):

    lines = []
    unimp_call_counter = Counter()
    exit_status = None
    last_exception = None

    def will_start_run_callback(self, state, *_args):
        state.cpu.emulate_until(0)

    def will_execute_syscall_callback(self, state, model):
        unimp = set(f.__name__
                    for f in set(getattr(state.platform, n) for n in dir(state.platform) if 'sys_' in n)
                    if is_unimplemented(f))
        name = str(model.__name__)

        # TODO - figure out a a away to recover the decorator directly from the model
        # This will break if one leaves a stub in the stubs file, but implements it anyway
        if name in unimp or name in stubs:
            self.unimp_call_counter.update({name: 1})

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

    def will_terminate_state_callback(self, current_state, current_state_id, e):
        self.last_exception = e
        message = str(e)
        if 'finished with exit status' in message:
            self.exit_status = int(message.split('status: ')[-1])


def collect_manticore_trace():
    m = Manticore(args.filename, argv=args.args, concrete_start=open(args.stdin_abspath, 'rb').read())
    plug = TracerPlugin()

    def inner(manticore_instance: Manticore, plugin_instance: TracerPlugin, message_queue: queue.Queue):
        manticore_instance.verbosity(0)
        manticore_instance.register_plugin(plugin_instance)
        manticore_instance.run()

    messages = queue.Queue()
    proc = threading.Thread(target=inner, args=(m, plug, messages))
    try:
        proc.start()
        proc.join(args.timeout)  # TODO - handle timeout exception
    except:
        print("Got caught here for some reason")

    try:
        exception = messages.get(block=False)
    except queue.Empty:
        exception = None

    return plug, m


def collect_kernel_trace(workspace):

    os.chdir(workspace)

    subprocess.Popen(['sudo', '/usr/bin/trace-cmd', 'reset']).wait()

    tracer = subprocess.Popen(['sudo', '/usr/bin/trace-cmd', 'record', '-e', 'syscalls', '-F', args.abspath] + args.args,
                              stdin=subprocess.PIPE,
                              stdout=open('ktrace.stdout', 'w'),
                              stderr=open('ktrace.stderr', 'w'))
    tracer.communicate(input=open(args.stdin_abspath, 'rb').read())

    report = subprocess.Popen(['sudo',  '/usr/bin/trace-cmd', 'report'],
                              stdout=open('ktrace_report.stdout', 'w'),
                              stderr=open('ktrace_report.stderr', 'w')).wait()

    data = open('ktrace_report.stdout').readlines()
    return [repr(l) for l in process_trace(filter(lambda l: ':' in l, data))], tracer.returncode


def yamlify(ktrace, mtrace):

    klines = process_lines(ktrace)
    mlines = process_lines(mtrace)

    dump_lines('ktrace.yaml', klines)
    dump_lines('mtrace.yaml', mlines)

    update_left_from_right(klines, mlines)

    dump_lines('processed_ktrace.yaml', klines)
    dump_lines('processed_mtrace.yaml', mlines)

    return klines, mlines


def pretty_print_results(unimplemented: Counter, ratio, exception=None, status=(0,0)):
    if args.ratio:
        print(ratio)
        return

    kstat, mstat = status
    print("===========")
    print("Results:", "\n  ", "Native: exit", kstat, " | ", "Manticore:",
          "exit " + str(mstat) if exception is None else "Exception")
    print("   Similarity ratio:", ratio)
    print("===========")
    print("Unimplemented System calls:")
    for name, count in unimplemented.most_common():
        print('{0:4s} : {1}'.format(str(count), name))
    print("===========")
    print("Exceptions:")
    print(exception)



def main():
    print("Warnings:")

    tracer, mc = collect_manticore_trace()
    mtrace = tracer.lines
    ktrace, kcode = collect_kernel_trace(mc.workspace)

    with open('ktrace', 'w') as kfile:
        for line in ktrace:
            kfile.write(line + '\n')
    with open('mtrace', 'w') as mfile:
        for line in mtrace:
            mfile.write(line + '\n')

    yamlify(ktrace, mtrace)

    ratio = files_ratio('processed_ktrace.yaml', 'processed_mtrace.yaml')

    pretty_print_results(tracer.unimp_call_counter, ratio, tracer.last_exception, (kcode, tracer.exit_status))


if __name__ == '__main__':
    main()

# TODO:
    # Pretty print output
    # Save Manticore log to file

