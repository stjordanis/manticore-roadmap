#! /usr/bin/env python

import argparse
import os
import difflib
from process_file import process_lines, dump_lines

arg_pointer_indices = {'mprotect': [0],
                       'newfstat': [1],
                       'rt_sigaction': [1, 2],
                       'accept': [1, 2], 'access': [0], 'bind': [1], 'chdir': [0], 'chmod': [0], 'chown': [0], 'chroot': [0], 'clock_getres': [1], 'clock_gettime': [1], 'clock_nanosleep': [2, 3], 'clock_settime': [1], 'clone': [2, 3], 'connect': [1], 'creat': [0], 
                       'faccessat': [1], 'fchmodat': [1], 'fchownat': [1], 'fstat': [1], 'fstatfs': [1], 'getcwd': [0], 'getpeername': [1, 2], 'getresgid': [0, 1, 2], 'getresuid': [0, 1, 2], 'getsockname': [1, 2], 'getsockopt': [3, 4], 'gettimeofday': [0, 1], 'lchown': [0], 
                       'link': [0, 1], 'linkat': [1, 3], 'lstat': [0, 1], 'mincore': [2], 'mkdir': [0], 'mknod': [0], 'mknodat': [1], 'mount': [0, 1, 2, 4], 'mq_notify': [1], 'mq_open': [0, 3], 'mq_timedreceive': [1, 3, 4], 'mq_timedsend': [1, 4], 'mq_unlink': [0], 'msgctl': [2], 
                       'msgrcv': [1], 'msgsnd': [1], 'open': [0], 'openat': [1], 'pipe': [0], 'read': [1], 'readlink': [0, 1], 'readlinkat': [1, 2], 'reboot': [3], 'recvfrom': [1, 4, 5], 'recvmsg': [1], 'rename': [0, 1], 'renameat': [1, 3], 'renameat2': [1, 3], 'rmdir': [0], 
                       'select': [1, 2, 3, 4], 'semop': [1], 'sendmsg': [1], 'sendto': [1, 4], 'setdomainname': [0], 'sethostname': [0], 'setsockopt': [3], 'settimeofday': [0, 1], 'shmat': [1], 'shmctl': [2], 'shmdt': [0], 'socketpair': [3], 'stat': [0, 1], 'statfs': [0, 1], 
                       'swapoff': [0], 'swapon': [0], 'symlink': [0, 1], 'symlinkat': [0, 2], 'syslog': [1], 'time': [0], 'timer_create': [1, 2], 'timer_gettime': [1], 'timer_settime': [2, 3], 'timerfd_gettime': [1], 'timerfd_settime': [2, 3], 'truncate': [0], 'unlink': [0], 
                       'unlinkat': [1], 'uselib': [0], 'ustat': [1], 'utime': [0, 1], 'wait4': [1, 3], 'waitid': [2, 4], 'write': [1]}

ignore_ret_mismatch = {'mmap', 'brk', 'getpid', 'geteuid'}


def test_is_same_line(left, right):
    name_match = left.name == right.name
    args_match = len(left.args) == len(right.args)
    rets_match = type(left.ret) == type(right.ret)
    if name_match and args_match and rets_match:
        return True
    else:
        if name_match and args_match and not rets_match:
            if left.name in ignore_ret_mismatch:
                return True
        else:
            print(f"Mismatch between lines: <<< {left} ||| {right} >>>")
            return False

def get_sequence_matcher(left_lines, right_lines, attr='name'):
    return difflib.SequenceMatcher(a=[getattr(i, attr) for i in left_lines],
                                   b=[getattr(i, attr) for i in right_lines])

def get_matching_lines(left, right):
    for lindex, rindex, num in get_sequence_matcher(left, right).get_matching_blocks():
        yield from zip(left[lindex:lindex+num], right[rindex:rindex+num])

def record_ret_mismatch(left, right):
    with open('ret_mismatch.txt', 'a') as rfile:
        rfile.write(f"{left.name}({', '.join(str(a) for a in left.args)}) --> [{str(left.ret)}, {str(right.ret)}]\n")

def record_arg_mismatch(left, right):
    args = []
    for l, r in zip(left.args, right.args):
        if l == r:
            args.append(l)
        else:
            args.append([l, r])
    with open('arg_mismatch.txt', 'a') as afile:
        afile.write(f"{left.name}({', '.join(str(a) for a in args)}) --> {str(left.ret)}\n")

def check_for_ret_arg_mismatch(left, right):
    if left.name != right.name:
        print("Name mismatch! Panicking")
        return
    if all(l==r for l, r in zip(left.args, right.args)):
        if left.ret != right.ret:
            record_ret_mismatch(left, right)
    if left.ret == right.ret:
        if sum(0 if l == r else 1 for l, r in zip(left.args, right.args)) == 1:
            record_arg_mismatch(left, right)

def update_left_from_right(left, right):
        for l, r in get_matching_lines(left, right):
            if test_is_same_line(l, r):
                for i in range(len(r.args)):
                    if type(r.args[i]) is str and type(l.args[i]) is int:
                        r.args[i] = '_PTR'
                        l.args[i] = '_PTR'
                    if l.args[i] != r.args[i]:
                        if l.name in arg_pointer_indices and i in arg_pointer_indices[l.name]:
                            r.args[i] = '_PTR'
                            l.args[i] = '_PTR'
                if l.ret != r.ret and l.name in ignore_ret_mismatch:
                    l.ret = 'IGNORED'
                    r.ret = 'IGNORED'

        for l, r in get_matching_lines(left, right):
            check_for_ret_arg_mismatch(l, r)

def main():
    parser = argparse.ArgumentParser(description='Parse a trace file into YAML')
    parser.add_argument('target', help="Name of the file to parse traces for")
    parser.add_argument('--verbose', '-v', action='count', help="Output verbosity")
    args = parser.parse_args()

    target = os.path.basename(args.target)

    with open(f'{target}.ktrace', 'r') as kfile:
        klines = process_lines(kfile.readlines(), args.verbose)

    with open(f'{target}.mtrace', 'r') as mfile:
        mlines = process_lines(mfile.readlines(), args.verbose)

    update_left_from_right(klines, mlines)

    processed_path = 'processed'
    os.makedirs(processed_path, exist_ok=True)

    dump_lines(os.path.join(processed_path, f'{target}.ktrace.yaml'), klines)
    dump_lines(os.path.join(processed_path, f'{target}.mtrace.yaml'), mlines)



if __name__ == '__main__':
    main()
