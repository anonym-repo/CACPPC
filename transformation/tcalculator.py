import taints
from taints import T_method__, T_scope__
from taints import taint_expr__ as T_

import string


def is_digit(i):
    with T_method__('is_digit', [i]) as T:
        return T(T(i) in T(string).digits)


def check_1(t):
    with T_method__('check_1', [t]) as T:
        T(print(T([i for i in [T(1), T(2), T(3)]])))


def check(t):
    with T_method__('check', [t]) as T:
        with T_scope__('for', 1, T) as T:
            for i in T_([1, 2, 3], T):
                T(print(T(i)))


def parse_num(s, i):
    with T_method__('parse_num', [s, i]) as T:
        n = T('')
        with T_scope__('while', 1, T) as T:
            while T_(s[i:] and is_digit(s[i]), T):
                n += T(s)[T(i)]
                i = T(T(i) + T(1))
        return T((T(i), T(n)))


def parse_paren(s, i):
    with T_method__('parse_paren', [s, i]) as T:
        assert T(T(s)[T(i)] == T('('))
        i, v = T(parse_expr(T(s), T(T(i) + T(1))))
        with T_scope__('if', 1, T) as T:
            if T_(s[i:] == '', T):
                raise T(Exception(T(s), T(i)))
        assert T(T(s)[T(i)] == T(')'))
        return T((T(T(i) + T(1)), T(v)))


def parse_expr(s, i=0):
    with T_method__('parse_expr', [s, i]) as T:
        expr = T([])
        is_op = T(True)
        with T_scope__('while', 1, T) as T:
            while T_(s[i:], T):
                c = T(s)[T(i)]
                with T_scope__('if', 1, T) as T:
                    if T_(c in string.digits, T):
                        with T_scope__('if', 2, T) as T:
                            if T_(not is_op, T):
                                raise T(Exception(T(s), T(i)))
                        i, num = T(parse_num(T(s), T(i)))
                        T(expr.append(T(num)))
                        is_op = T(False)
                    elif c in ['+', '-', '*', '/']:
                        if is_op:
                            raise Exception(s, i)
                        expr.append(c)
                        is_op = True
                        i = i + 1
                    elif c == '(':
                        if not is_op:
                            raise Exception(s, i)
                        i, cexpr = parse_paren(s, i)
                        expr.append(cexpr)
                        is_op = False
                    elif c == ')':
                        break
                    else:
                        raise Exception(s, i)
        with T_scope__('if', 3, T) as T:
            if T_(is_op, T):
                raise T(Exception(T(s), T(i)))
        return T((T(i), T(expr)))


def main(arg):
    with T_method__('main', [arg]) as T:
        return T(parse_expr(T(arg)))

if __name__ == "__main__":
    import sys
    js = []
    for arg in sys.argv[1:]:
        with open(arg) as f:
            mystring = f.read().strip().replace('\n', ' ')
        tainted_input = taints.wrap_input(mystring)
        main(tainted_input)

