#!/usr/bin/env python

from sys import stdin


class Call:
    def __init__(self, name:str, args:list, ret:int):
        self.name = name
        self.args = args
        self.ret = ret

    def __repr__(self):
        return f"{self.name}({', '.join(shorten_hex(a) for a in self.args)}) = {self.ret}"


def process_line(line):
    header = line.split(':')[0].strip()
    args = [t.split(':')[-1].strip() for t in line.split(', ')]
    if line.startswith('enter'):
        return Call(header.replace('enter_', ''), args, None)
    if line.startswith('exit'):
        return Call(header.replace('exit_', ''), None, args[0])


def merge(arg_part, ret_part):
    return Call(arg_part.name, arg_part.args, ret_part.ret)


def shorten_hex(hex_str):
    if len(hex_str):
        return hex(int(hex_str, 16))
    return hex_str


def process_trace(lines):
    call_stack = []

    for line in lines:
        line = line.split(': sys_')[1].strip()
        linedata = process_line(line)
        if line.startswith('enter_'):
            call_stack.append(linedata)
        elif line.startswith('exit_') and call_stack and call_stack[-1].name == linedata.name:
            call_stack.append(merge(call_stack.pop(), linedata))

    for c in call_stack:
        print(c)

    return call_stack


if __name__ == '__main__':
    process_trace(stdin.readdlines())