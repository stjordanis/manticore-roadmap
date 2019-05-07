from .config import args
from manticore.native import Manticore
from manticore.core.plugin import Plugin
from manticore.utils import log
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
import time
import logging
import io

logstream = io.StringIO()


def monkey_patch_handlers():
    for logger in logging.root.manager.loggerDict.values():
        if isinstance(logger, logging.Logger):
            for h in logger.handlers:
                assert isinstance(h, logging.StreamHandler)
                h.setFormatter(logging.Formatter(("%(name)s:%(levelname)s %(message)s")))
                h.setStream(logstream)

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

    def inner(manticore_instance: Manticore, plugin_instance: TracerPlugin):
        manticore_instance.verbosity(0)
        monkey_patch_handlers()
        manticore_instance.register_plugin(plugin_instance)
        manticore_instance.run()

    proc = threading.Thread(target=inner, args=(m, plug))
    starttime = time.time()
    try:
        proc.start()
        proc.join(args.timeout)  # TODO - handle timeout exception
    except:
        pass  # Timed out

    m.elapsed = time.time() - starttime
    return plug, m


def collect_kernel_trace(workspace):

    os.chdir(workspace)

    subprocess.Popen(['sudo', '/usr/bin/trace-cmd', 'reset']).wait()

    starttime = time.time()
    tracer = subprocess.Popen(['sudo', '/usr/bin/trace-cmd', 'record', '-e', 'syscalls', '-F', args.abspath] + args.args,
                              stdin=subprocess.PIPE,
                              stdout=open('ktrace.stdout', 'w'),
                              stderr=open('ktrace.stderr', 'w'))
    tracer.communicate(input=open(args.stdin_abspath, 'rb').read())
    elapsed = time.time() - starttime

    report = subprocess.Popen(['sudo',  '/usr/bin/trace-cmd', 'report'],
                              stdout=open('ktrace_report.stdout', 'w'),
                              stderr=open('ktrace_report.stderr', 'w')).wait()

    data = open('ktrace_report.stdout').readlines()
    return [repr(l) for l in process_trace(filter(lambda l: ':' in l, data))], tracer.returncode, elapsed


def yamlify(ktrace, mtrace):

    klines = process_lines(ktrace)
    mlines = process_lines(mtrace)

    dump_lines('ktrace.yaml', klines)
    dump_lines('mtrace.yaml', mlines)

    update_left_from_right(klines, mlines)

    dump_lines('processed_ktrace.yaml', klines)
    dump_lines('processed_mtrace.yaml', mlines)

    return klines, mlines


def pretty_print_results(unimplemented: Counter, ratio, exception=None, status=(0,0), elapsed=(0,0)):
    if args.ratio:
        print(ratio)
        return

    kstat, mstat = status
    print("Results:")
    m, s = divmod(elapsed[0], 60)
    print(f'{int(m)}m {s:.02f}s', "Native: Exit", kstat)
    m, s = divmod(elapsed[1], 60)
    print(f'{int(m)}m {s:.02f}s', "Manticore:", "Exit " + str(mstat) if exception is None else "Exception:", exception)
    print("Similarity ratio:", ratio)

    if len(unimplemented):
        print("\n---------------------------------------------\n")
        print("Unimplemented System calls:")
        for name, count in unimplemented.most_common():
            print('   {0:4s} : {1}'.format(str(count), name))

    logdata = logstream.getvalue().strip()
    if len(logdata):
        print("\n---------------------------------------------\n")
        print("Warnings and Exceptions:")
        print(logstream.getvalue())

    if os.path.exists('arg_mismatch.txt'):
        print("---------------------------------------------\n")
        print("System calls with mismatched arguments:")
        print(open('arg_mismatch.txt').read())

    if os.path.exists('ret_mismatch.txt'):
        print("---------------------------------------------\n")
        print("System calls with mismatched return values:")
        print(open('ret_mismatch.txt').read())


def main():
    tracer, mc = collect_manticore_trace()
    mtrace = tracer.lines
    ktrace, kcode, ktime = collect_kernel_trace(mc.workspace)

    with open('ktrace', 'w') as kfile:
        for line in ktrace:
            kfile.write(line + '\n')
    with open('mtrace', 'w') as mfile:
        for line in mtrace:
            mfile.write(line + '\n')

    yamlify(ktrace, mtrace)

    ratio = files_ratio('processed_ktrace.yaml', 'processed_mtrace.yaml')

    pretty_print_results(tracer.unimp_call_counter,
                         ratio,
                         tracer.last_exception,
                         (kcode, tracer.exit_status),
                         (ktime, mc.elapsed))


if __name__ == '__main__':
    main()

# TODO:
    # Save Manticore log to file

