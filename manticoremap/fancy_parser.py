from lark import Lark, Transformer
from base64 import b64decode
from copy import copy
import os

with open(os.path.join(os.getenv("PYTHONPATH", "/home/ehennenfent/syscalls"), 'trace.lark'), 'r') as gf:
    grammar = gf.read()


def try_convert(s):
    try:
        out = eval(s)
        if type(out) in {int, str}:
            return out
    except:
        return s
    return s

class TreeToTokens(Transformer):

    def null(self, _):
        return 0

    def unknown(self, _):
        return '?'

    def hex_literal(self, token_list):
        n = token_list[0]
        return int(n, 16)

    def name(self, n):
        return n[0]

    def argspec(self, args):
        if type(args) is list and len(args) == 1 and type(args[0]) is list:
            return args[0]
        return list(args)

    def sentence(self, arglist):
        return ' '.join(arglist)

    def str_literal(self, escaped_string):        
        return eval(str(escaped_string[0]).replace('...',''))

    def b64_literal(self, token):
        s = token[0].replace('B64STR:','')
        if not len(s):
            return ""
        return b64decode(s).decode('utf-8')

    def int_literal(self, t):
        if type(t) is list:
            return int(t[0])
        return int(t)

    def error_code(self, children):
        return int(children[0])

    def flag_union(self, _):
        return '_FLAG'
    
    def junk_list(self, _):
        return '_PTR_ARR'

    def junk_struct(self, _):
        return '_PTR_STRUCT'

    def junk_comment(self, _):
        return '_PTR'

    def kv_pair(self, pair):
        return pair[-1]

    def kv_pair_set(self, children):
        return [str(c) for c in children]

    def func(self, children):
        return list(children)

    def line(self, children):
        return str(children[0][0]), children[0][1], children[1],


class LineResult:

    def __type__(self):
        return dict

    def __init__(self, name, args, ret):
        # immutable backing values
        self._name = name
        self._args = args
        self._ret = ret

        # public attrs
        self.name = copy(self._name)
        self.args = copy(self._args)
        self.ret = copy(self._ret)

        self.escape_ret_val()

    def escape_ret_val(self):
        if self._ret in self._args and len(str(self._ret)) > 3:
            self.ret = 'RETVAL'
            self.args[self._args.index(self._ret)] = 'RETVAL'

    def yaml_dict(self):
        return {self.name: {'args': self.args,
                            'ret': try_convert(self.ret)}}

    def __str__(self):
        return f"{self.name}({', '.join(repr(i) for i in self.args)}) = {repr(self.ret)}" 

parser = Lark(grammar, debug=True, start='line')

def parse_line(line, v=0):
    raw = parser.parse(line)
    if v and v >= 2:
        print(raw.pretty())
    return LineResult(*TreeToTokens().transform(raw))
