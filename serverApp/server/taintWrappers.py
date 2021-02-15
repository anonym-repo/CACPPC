from collections import UserList, UserDict
import numpy as np
from io import TextIOWrapper, BufferedWriter

from sklearn import preprocessing
import sklearn.linear_model
import sklearn as sk

fd = open('output.txt', 'w')

def make_wrapper(fun):
    def proxy(self, *args, **kwargs):
        res = fun(self, *args, **kwargs)
        return self.create(res)
    return proxy

def make_proxy_wrapper(name):
    def proxy(self, *args, **kwargs):
        fun = getattr(self.obj, name)
        return fun(*args, **kwargs)
    return proxy

def informationflow_init():
    for name in dir(sk.preprocessing._data.StandardScaler):
        if name in ['__init__', '__new__', '__class__', '__dict__','__getattribute__', '__getattr__', '__dir__', '__setattr__']:
            continue
        setattr(tStandardScaler, name, make_proxy_wrapper(name))

    for name in dir(sk.linear_model._logistic.LogisticRegression):
        if name in ['__init__', '__new__', '__class__', '__dict__', '__getattribute__', '__getattr__', '__dir__', '__setattr__']:
            continue
        setattr(tLogisticRegression, name, make_proxy_wrapper(name))

def initialize():
    informationflow_init()
    INITIALIZER_LIST = [informationflow_init]
    for fn in INITIALIZER_LIST:
        fn()

def get_taint(func_name, input_taint):
    return 'HIGH'

def is_taint_greater(first, second):
    if first == "HIGH" and not second == "HIGH":
        return True
    if first == "LOW" and second == "None":
        return True

    return False

class ttuple(tuple):
    def __new__(cls, value, *args, **kw):
        return tuple.__new__(cls, value)

    def __init__(self, value, taint=None, **kwargs):
        self.taint = taint

class tbool(int):
    def __new__(cls, value, *args, **kw):
        return int.__new__(cls, value)

    def __init__(self, value, taint=None, **kwargs):
        self.taint = taint
#----------------------------The Wrapper class for string---------------------------------
class tstr(str):
    def __new__(cls, value, *args, **kw):
        return str.__new__(cls, value)

    def __init__(self, value, taint=None, parent=None, **kwargs):
        self.parent = parent
        self.taint = taint

    def __repr__(self):
        return tstr(str.__repr__(self), taint=self.taint)

    def __str__(self):
        return str.__str__(self)

    def clear_taint(self):
        self.taint = None
        return self

    def has_taint(self):
        return self.taint is not None

    def __add__(self, other):
        if hasattr(other, 'taint') and other.taint == "HIGH":
            pr_taint = other.taint
        else:
            pr_taint = self.taint
        return tstr((str(self) + str(other) ), taint=pr_taint)

    def create(self, res, taint):
        return tstr(res, taint, self)

    def __radd__(self, s):
        return self.create(s + str(self))

    def replace(self, a, b, n=None):
        old_taint = self.taint
        b_taint = b.taint if isinstance(b, tstr) else [None] * len(b)
        mystr = str(self)
        i = 0
        replaced = False
        while True:
            if n and i >= n:
                break
            idx = mystr.find(a)
            if idx == -1:
                break
            last = idx + len(a)
            mystr = mystr.replace(a, b, 1)
            replaced = True
            i += 1
        if replaced and is_taint_greater(b, a):
            old_taint = b_taint
        return self.create(mystr, old_taint)

    def _split_helper(self, sep, splitted):
        result_list = []
        last_idx = 0
        first_idx = 0
        sep_len = len(sep)

        for s in splitted:
            last_idx = first_idx + len(s)
            item = self[first_idx:last_idx]
            result_list.append(item)
            first_idx = last_idx + sep_len
        return result_list

    def _split_space(self, splitted):
        result_list = []
        last_idx = 0
        first_idx = 0
        sep_len = 0
        for s in splitted:
            last_idx = first_idx + len(s)
            item = self[first_idx:last_idx]
            result_list.append(item)
            v = str(self[last_idx:])
            sep_len = len(v) - len(v.lstrip(' '))
            first_idx = last_idx + sep_len
        return result_list

    def rsplit(self, sep=None, maxsplit=-1):
        splitted = super().rsplit(sep, maxsplit)
        if not sep:
            return self._split_space(splitted)
        return self._split_helper(sep, splitted)

    def split(self, sep=None, maxsplit=-1):
        splitted = tlist(super().split(sep, maxsplit), self.taint)
        if not sep:
            return tlist(self._split_space(splitted), self.taint)
        return tlist(self._split_helper(sep, splitted), self.taint)


#----------------------------The Wrapper class for integer---------------------------------
class tint(int):
    def __new__(cls, value, *args, **kw):
        return int.__new__(cls, value)

    def __init__(self, value, taint=None, **kwargs):
        self.taint = taint

    def __repr__(self):
        s = int.__repr__(self)
        return tstr(s, taint=self.taint)

    def __str__(self):
        return tstr(int.__str__(self), taint=self.taint)

    def __int__(self):
        return int.__int__(self)

    def clear_taint(self):
        self.taint = None
        return self

    def has_taint(self):
        return self.taint is not None

    def create(self, n):
        return tint(n, taint=self.taint)

    def __add__(self, other):
        if hasattr(other, 'taint') and other.taint == "HIGH":
            pr_taint = other.taint
        else:
            pr_taint = self.taint
        return tint(int(self) + int(other) , taint=pr_taint)

#----------------------------The Wrapper class for float---------------------------------
class tfloat(float):
    def __new__(cls, value, *args, **kw):
        return float.__new__(cls, value)

    def __init__(self, value, taint=None, **kwargs):
        self.taint = taint

    def __repr__(self):
        s = float.__repr__(self)
        return tstr(s, taint=self.taint)

    def __str__(self):
        return tstr(float.__str__(self), taint=self.taint)

    def __float__(self):
        return float.__float__(self)

    def clear_taint(self):
        self.taint = None
        return self

    def has_taint(self):
        return self.taint is not None

    def create(self, n):
        return tfloat(n, taint=self.taint)

    def __add__(self, other):
        if hasattr(other, 'taint') and other.taint == "HIGH":
            pr_taint = other.taint
        else:
            pr_taint = self.taint
        return tfloat(float(self) + float(other) , taint=pr_taint)

#----------------------------The Wrapper class for list---------------------------------
class tlist(UserList):
    cpyNum = 0
    def __init__(self, liste, taint=None):
        self.taint_counter = {}
        self.taint = taint
        if taint == None:
             super().__init__(liste)
             for dt in self.data:
                 if hasattr(dt, 'taint'):
                     self.inc_taint(dt.taint)
        else:
            super().__init__({})
            for dt in liste:
                if isinstance(dt, str):
                    self.data.append(tstr(dt, taint))
                elif isinstance(dt, int):
                    self.data.append(tint(dt, taint))
                elif isinstance(dt, bool): self.data.append(tbool(dt, taint))
                elif isinstance(dt, tuple): self.data.append(ttuple(dt, taint))
                elif isinstance(dt, float): self.data.append(tfloat(dt, taint))
                elif isinstance(dt, list): self.data.append(tlist(dt, taint))
                elif isinstance(dt, dict): self.data.append(tdict(dt, taint))
                elif isinstance(dt, np.ndarray): self.data.append(tndarray(dt, taint))
                elif isinstance(dt, preprocessing._data.StandardScaler): self.data.append(tStandardScaler(dt, taint))
                elif isinstance(dt, sklearn.linear_model._logistic.LogisticRegression): self.data.append(tLogisticRegression(dt, taint))
                elif isinstance(dt, TextIOWrapper): self.data.append(tTextIOWrapper(dt, taint))
                elif isinstance(dt, BufferedWriter): self.data.append(tBufferedWriter(dt, taint))
                else: self.data.append(dt)
                self.inc_taint(taint)

        self.set_taint_helper()


    def __setitem__(self, i, item):
        if i == len(self.data):
            self.data.append(item)
        else:
            self.data[i] = item
        if hasattr(item, 'taint'):
            self.inc_taint(item.taint)

        self.set_taint_helper()


    def __getitem__(self, key):
        value = super().__getitem__(key)
        if hasattr(value, 'taint'):
            return value
        return value

    def __delitem__(self, i):
        self.pop(i)

    def pop(self, i):
        elem = super().pop(i)
        if hasattr(elem, 'taint'):
            self.dec_taint(elem.taint)
        return elem

    def remove(self, item):
        idx = super().index(item)
        elem = super().pop(idx)
        if hasattr(elem, 'taint'):
            self.dec_taint(elem.taint)


    def append(self, item):
        self.data.append(item)
        if hasattr(item, 'taint'):
            self.inc_taint(item.taint)

        self.set_taint_helper()

    def highest_taint(self):
        return self.highest_taint


    def __repr__(self):
        return f"{type(self).__name__}({super().__repr__()}, {self.highest_taint})"


    def set_taint_helper(self):
        if 'HIGH' in self.taint_counter:
           self.highest_taint = 'HIGH'
           self.taint = 'HIGH'
        elif 'LOW' in self.taint_counter:
           self.highest_taint = 'LOW'
           self.taint = 'LOW'
        else:
           self.highest_taint = None


    def inc_taint(self, taint):
        if not taint in self.taint_counter:
            self.taint_counter[taint] = 1
        else:
            self.taint_counter[taint] += 1


    def dec_taint(self, taint):
        self.taint_counter[taint] -= 1
        if self.taint_counter[taint] == 0:
            del self.taint_counter[taint]
            self.set_taint_helper()

    def copy(self):
        tmpTlist = tlist(super().copy(), self.taint)
        tmpTlist.highest_taint = self.highest_taint
        return tmpTlist

#----------------------------The Wrapper class for dictionary---------------------------------
class tdict(UserDict):

    def __init__(self, dicte, taint=None):
        self.taint_counter = {}
        self.taint = taint
        if taint == None:
             super().__init__(dicte)
        else:
             super().__init__({})
             for key, value in dicte.items():
                 if isinstance(value, str):
                     self.data[key] = tstr(value, taint)
                 elif isinstance(value, int):
                     self.data[key] = tint(value, taint)
                 elif isinstance(value, float):
                    pass
                 self.inc_taint(taint)

        self.set_taint_helper()


    def __delitem__(self, key):
        value = self.data.pop(key)
        if hasattr(value, 'taint'):
            self.dec_taint(value.taint)
        self.set_taint_helper()

    def __setitem__(self, key, value):
        if key in self:
            old_val = self.data[key]
            if hasattr(old_val, 'taint'):
                self.dec_taint(old_val.taint)
        super().__setitem__(key, value)
        if hasattr(value, 'taint'):
            self.inc_taint(value.taint)
        self.set_taint_helper()

    def __repr__(self):
        return f"{type(self).__name__}({super().__repr__()}, {self.highest_taint})"

    def set_taint_helper(self):
        if 'HIGH' in self.taint_counter:
           self.highest_taint = 'HIGH'
           self.taint = 'HIGH'
        elif 'LOW' in self.taint_counter:
           self.highest_taint = 'LOW'
           self.taint = 'LOW'
        else:
           self.highest_taint = None


    def inc_taint(self, taint):
        if not taint in self.taint_counter:
            self.taint_counter[taint] = 1
        else:
            self.taint_counter[taint] += 1


    def dec_taint(self, taint):
        self.taint_counter[taint] -= 1
        if self.taint_counter[taint] == 0:
            del self.taint_counter[taint]
            self.set_taint_helper()


#----------------------------The Wrapper class for ndarray--------------------------------
class tndarray(np.ndarray):

    def __new__(cls, input_array, taint=None):
        obj = np.asarray(input_array).view(cls)
        obj.taint = taint
        return obj

    def __array_finalize__(self, obj):
        if obj is None: return
        self.taint = getattr(obj, 'taint', None)


class tStandardScaler():
    def __init__(self, standardScaler, taint=None):
        self.obj = standardScaler
        self.taint = taint


#----------------------------The Wrapper class for LogisticRegression--------------------------------
class tLogisticRegression():
    def __init__(self, logisticRegression, taint=None):
        self.obj = logisticRegression
        self.taint = taint

    @property
    def coef_(self):
        return self.obj.coef_

    @coef_.setter
    def coef_(self, value):
        self.obj.coef_ = value

#----------------------------The Wrapper class for TextIOWrapper--------------------------------
class tTextIOWrapper(TextIOWrapper):

    def __init__(self, textIOWarpper, taint=None):
        self._taint = taint
        self.textIOWarpper = textIOWarpper

    @property
    def taint(self):
        return self._taint

    @taint.setter
    def taint(self, value):
        self._taint = value

    def readline(self):
        try:
            return self.textIOWarpper.readline()
        except AttributeError:
            buffer = bytes()
            c = self.read(1)
            while len(c) > 0:
                buffer += c
                if c == b"\n":
                    break
                c = self.read(1)
            return buffer

    def readlines(self, hint=None):
        try:
            return tlist(self.textIOWarpper.readlines(hint), self.taint)
        except AttributeError:
            lines = list()
            line = self.readline()
            while len(line) > 0:
                lines.append(line)
                line = self.readline()
            return lines

    def read(self, size=-1):
        try:
            return self.textIOWarpper.read(size)
        except AttributeError:
            raise io.UnsupportedOperation('Stream does not support reading')

    def readall(self):
        try:
            return self.textIOWarpper.readall()
        except AttributeError:
            buffer = bytes()
            b = self.textIOWarpper.read(4096)
            while len(b) > 0:
                buffer += b
                b = self.textIOWarpper.read(4096)
            return buffer
    def flush(self):
        self.textIOWarpper.flush()

    def write(self, value):
        if hasattr(value, 'taint'):
            if is_taint_greater(value.taint, self.taint):
                self.taint = value.taint

        self.textIOWarpper.write(str(value))


#----------------------------The Wrapper class for BufferedWriter--------------------------------

class tBufferedWriter(BufferedWriter):

    def __init__(self, BufferedWriter, taint=None):
        self._taint = taint
        self.bufferedWriter = BufferedWriter

    @property
    def taint(self):
        return self._taint

    @taint.setter
    def taint(self, value):
        self._taint = value

    def readline(self, limit=None):
        try:
            return self.bufferedWriter.readline()
        except AttributeError:
            raise io.UnsupportedOperation('Stream does not support reading')

    def readlines(self, hint=None):
        try:
            return tlist(self.bufferedWriter.readlines(hint), self.taint)
        except AttributeError:
            raise io.UnsupportedOperation('Stream does not support reading')

    def read(self, size=-1):
        try:
            return self.bufferedWriter.read(size)
        except AttributeError:
            raise io.UnsupportedOperation('Stream does not support reading')

    def readall(self):
        try:
            return self.bufferedWriter.readall()
        except AttributeError:
            buffer = bytes()
            b = self.bufferedWriter.read(4096)
            while len(b) > 0:
                buffer += b
                b = self.bufferedWriter.read(4096)
            return buffer

    def write(self, value):
        if hasattr(value, 'taint'):
            if is_taint_greater(value.taint, self.taint):
                self.taint = value.taint

        self.bufferedWriter.write(value)


initialize()
