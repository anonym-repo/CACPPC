from __future__ import division
from server import server, db, bcrypt, state_machine
from server.models import User, State, Action_capability
from flask_login import  current_user

from pyparsing import (Literal, CaselessLiteral, Word, Combine, Group, Optional,
                       ZeroOrMore, Forward, nums, alphas, oneOf)
import math
import operator
import networkx as nx
import matplotlib.pyplot as plt

import os
import os.path
import pickle

class NumericStringParser(object):

    def pushFirst(self, strg, loc, toks):
        self.exprStack.append(toks[0])

    def pushUMinus(self, strg, loc, toks):
        if toks and toks[0] == '-':
            self.exprStack.append('unary -')

    def __init__(self):
        point = Literal(".")
        e = CaselessLiteral("E")
        fnumber = Combine(Word("+-" + nums, nums) +
                          Optional(point + Optional(Word(nums))) +
                          Optional(e + Word("+-" + nums, nums)))
        ident = Word(alphas, alphas + nums + "_$")
        plus = Literal("+")
        minus = Literal("-")
        mult = Literal("*")
        div = Literal("/")
        lpar = Literal("(").suppress()
        rpar = Literal(")").suppress()
        addop = plus | minus
        multop = mult | div
        expop = Literal("^")
        pi = CaselessLiteral("PI")
        expr = Forward()
        atom = ((Optional(oneOf("- +")) +
                 (ident + lpar + expr + rpar | pi | e | fnumber).setParseAction(self.pushFirst))
                | Optional(oneOf("- +")) + Group(lpar + expr + rpar)
                ).setParseAction(self.pushUMinus)

        factor = Forward()
        factor << atom + \
            ZeroOrMore((expop + factor).setParseAction(self.pushFirst))
        term = factor + \
            ZeroOrMore((multop + factor).setParseAction(self.pushFirst))
        expr << term + \
            ZeroOrMore((addop + term).setParseAction(self.pushFirst))

        self.bnf = expr
        # map operator symbols to corresponding arithmetic operations
        epsilon = 1e-12
        self.opn = {"+": operator.add,
                    "-": operator.sub,
                    "*": operator.mul,
                    "/": operator.truediv,
                    "^": operator.pow}
        self.fn = {"sin": math.sin,
                   "cos": math.cos,
                   "tan": math.tan,
                   "exp": math.exp,
                   "abs": abs,
                   "trunc": lambda a: int(a),
                   "round": round,
                   "sgn": lambda a: abs(a) > epsilon and cmp(a, 0) or 0}

    def evaluateStack(self, s):
        op = s.pop()
        if op == 'unary -':
            return -self.evaluateStack(s)
        if op in "+-*/^":
            op2 = self.evaluateStack(s)
            op1 = self.evaluateStack(s)
            return self.opn[op](op1, op2)
        elif op in self.fn:
            return self.fn[op](self.evaluateStack(s))
        elif op[0].isalpha():
            return 0
        else:
            return float(op)

    def eval(self, num_string, parseAll=True):
        self.exprStack = []
        results = self.bnf.parseString(num_string, parseAll)
        val = self.evaluateStack(self.exprStack[:])
        return val

def get_current_state():
    user_id = current_user.id
    state = State.query.filter_by(user_id=user_id).first()
    return state.current_state

def get_all_taints():
    user_id = current_user.id
    state = State.query.filter_by(user_id=user_id).first()
    return state.acc_taint, state.model_taint, state.data_taint, state.scaler_taint

def set_all_taints(new_acc, new_model, new_data, new_scaler):
    user_id = current_user.id
    state = State.query.filter_by(user_id=user_id).first()
    state.acc_taint = new_acc
    state.model_taint = new_model
    state.data_taint = new_data
    state.scaler_taint = new_scaler
    db.session.commit()


def get_acc_taint():
    user_id = current_user.id
    state = State.query.filter_by(user_id=user_id).first()
    return state.acc_taint

def set_acc_taint(new_taint):
    user_id = current_user.id
    state = State.query.filter_by(user_id=user_id).first()
    state.acc_taint = new_taint
    db.session.commit()

def get_model_taint():
    user_id = current_user.id
    state = State.query.filter_by(user_id=user_id).first()
    return state.model_taint

def set_model_taint(new_taint):
    user_id = current_user.id
    state = State.query.filter_by(user_id=user_id).first()
    state.model_taint = new_taint
    db.session.commit()

def get_data_taint():
    user_id = current_user.id
    state = State.query.filter_by(user_id=user_id).first()
    return state.acc_taint

def set_data_taint(new_taint):
    user_id = current_user.id
    state = State.query.filter_by(user_id=user_id).first()
    state.model_taint = new_taint
    db.session.commit()

def get_scaler_taint():
    user_id = current_user.id
    state = State.query.filter_by(user_id=user_id).first()
    return state.scaler_taint

def set_scaler_taint(new_taint):
    user_id = current_user.id
    state = State.query.filter_by(user_id=user_id).first()
    state.scaler_taint = new_taint
    db.session.commit()


def set_user_state(to_state):
    user_id = current_user.id
    state = State.query.filter_by(user_id=user_id).first()
    state.current_state = to_state
    db.session.commit()

def filter_actions_by_caps(actions):
    return actions

def create_user(username, email,
                password, firstname,
                lastname, is_admin=False):

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    user = User(username=username, email=email,
                 password=hashed_password,
                 firstname=firstname, lastname=lastname, is_admin=is_admin)


    db.session.add(user)
    db.session.commit()

    state = State(user_id=user.id, acc_taint='None', model_taint='None', data_taint='None', scaler_taint='None')
    db.session.add(state)
    db.session.commit()

def get_parameters_types_of_action(act_name, prarms_set_name):
    current_state = get_current_state()
    action = state_machine.get_action_by_name_at(current_state, act_name)

    types = action.get_parameters_type(prarms_set_name)
    return types

def is_int(s):
    if s[0] in ('-', '+'):
        return s[1:].isdigit()
    return s.isdigit()

def parse_listkv(param_value, orig_type):
    param_list = []
    error = None

    all_params = param_value.split(",")
    for elm in all_params:
        if elm == '':
            break
        tmp_val = elm.split("=")
        if len(tmp_val) == 2 :
            param_list.append((tmp_val[0].rstrip().lstrip(), tmp_val[1].rstrip().lstrip()))
        else:
            return param_list, "Keys and values should be sparated by a \'=\'"

    for elm in param_list:
        if orig_type == 'integer':
            if not is_int(elm[1]):
                error = "parameter " + elm[0] + " should be an integer"
            else:
                try:
                    elm[1] = int(parser.eval(elm[1]))
                except:
                    error = "parameter " + elm[0] + " should be an integer or parsable mathematical expression"
        elif orig_type =='float':
            try:
                elm[1] = parser.eval(elm[1])
            except:
                error = "parameter " + key + " should be a float or parsable mathematical expression"

        if error != None:
            param_list = []
            return param_list, error
    return param_list, error

def check_and_convert_parameteres(parameters, types):
    errors = list()
    parser = NumericStringParser()
    for key in parameters.keys():
        orig_type = types[key]

        if orig_type == 'integer':
            if not is_int(parameters[key]):
                errors.append("parameter " + key + " should be an integer")
            else:
                try:
                    parameters[key] = int(parser.eval(parameters[key]))
                except:
                    errors.append("parameter " + key +
                                  " should be an integer or parsable mathematical expression")
        elif orig_type =='float':
            try:
                parameters[key] = parser.eval(parameters[key])

            except:
                errors.append("parameter " + key +
                              " should be a float or parsable mathematical expression")
        elif orig_type.startswith('listkv'):
             param_list, error = parse_listkv(parameters[key], orig_type[7:])
             if error != None:
                 errors.append(error)

             else:
                 parameters[key] = param_list
        else:
            pass

    return errors

def extract_params(form_data):
    act_name = form_data['action']
    params = {}
    errors = []

    if act_name == 'None':
        return dict(), dict()

    par_set_key = 'selection-params-set_' + act_name

    if par_set_key not in form_data.keys():
        return params, errors

    params_set_name = form_data[par_set_key]

    types = get_parameters_types_of_action(act_name, params_set_name)
    params = dict()

    prefix = "param__" + act_name + "__paramset__" + params_set_name
    filtered_params =  dict(filter(lambda elem: elem[0].startswith(prefix), form_data.items()))
    for key in filtered_params.keys():
        #new_key = key[len(prefix):]
        new_key =  key.split("__")[-1]
        params[new_key] = filtered_params[key]

    errors = check_and_convert_parameteres(params, types)

    return params, errors

def reset_state():
    set_user_state(0)
    set_all_taints('None', 'None', 'None', 'None')
    prefix = './output_files/id_' + str(current_user.id) + '_state_' + str(0)
    acc_filename = prefix + '_acc'
    model_filename = prefix + '_model'
    data_filename = prefix + '_data'
    scaler_filename = prefix + '_scaler'

    if os.path.exists(acc_filename):
        os.remove(acc_filename)
        os.remove(model_filename)
        os.remove(data_filename)
        os.remove(scaler_filename)

    file_name = './output_files/id_' + str(current_user.id) + '_state_taints.txt'
    if os.path.exists(file_name):
        with open(file_name, 'w') as f:
            line = "0\n"
            f.write(line)
            f.close()

def select_raw_data(level):
    fileList = []
    for root, dirs, files in os.walk("./raw_data"):
        for filename in files:
            fileList.append(filename)
    return fileList

def findStateTaintsInFile(lines, state):
    for line in lines:
        if line.startswith(str(state)):
            return lines.index(line)
    return -1

def getSateStateTaintsInFile(user_id, state):
    file_name = './output_files/id_' + str(user_id) + '_state_taints.txt'
    if os.path.exists(file_name):
        with open(file_name, 'r') as f:
            lines = f.readlines()
            f.close()
    else:
        return False, []

    idx = findStateTaintsInFile(lines, state)
    if idx == -1:
        return False, []
    else:
        taints = lines[idx].rstrip("\n").split(' ')
        del taints[0]
        return True, taints

def updateStateTaintsInFile(user_id, state, taints):
    file_name = './output_files/id_' + str(user_id) + '_state_taints.txt'
    if os.path.exists(file_name):
        #append_write = 'a'
        with open(file_name, 'r') as f:
            lines = f.readlines()
            f.close()
    else:
        #append_write = 'w'
        lines = []

    idx = findStateTaintsInFile(lines, state)
    newStr = str(state) + " " + " ".join(str(item) for item in taints)+ "\n"
    if idx == -1:
        lines.append(newStr)
    else:
        lines[idx] = newStr

    with open(file_name, 'w') as f:
        for line in lines:
            f.write(line)
        f.close()

def correct_tmp_filenames(user_id, to_state):
    prefix = './output_files/id_' + str(user_id) + '_state_' + str(to_state)
    acc_filename = prefix + '_acc'
    model_filename = prefix + '_model'
    data_filename = prefix + '_data'
    scaler_filename = prefix + '_scaler'

    tmp_acc_filename = prefix + '_tmp' + '_acc'
    tmp_model_filename = prefix + '_tmp' + '_model'
    tmp_data_filename = prefix + '_tmp' + '_data'
    tmp_scaler_filename = prefix + '_tmp' + '_scaler'

    os.remove(acc_filename)
    os.remove(model_filename)
    os.remove(data_filename)
    os.remove(scaler_filename)

    os.rename(tmp_acc_filename, acc_filename)
    os.rename(tmp_model_filename, model_filename)
    os.rename(tmp_data_filename, data_filename)
    os.rename(tmp_scaler_filename, scaler_filename)

def transfer_files(user_id, current_state, to_state):
    prefix = './output_files/id_' + str(user_id) + '_state_' + str(current_state)
    current_state_acc_filename = prefix + '_acc'
    current_state_model_filename = prefix + '_model'
    current_state_data_filename = prefix + '_data'
    current_state_scaler_filename = prefix + '_scaler'

    prefix = './output_files/id_' + str(user_id) + '_state_' + str(to_state)
    to_state_acc_filename = prefix + '_acc'
    to_state_model_filename = prefix + '_model'
    to_state_data_filename = prefix + '_data'
    to_state_scaler_filename = prefix + '_scaler'

    os.rename(current_state_acc_filename, to_state_acc_filename)
    os.rename(current_state_model_filename, to_state_model_filename)
    os.rename(current_state_data_filename, to_state_data_filename)
    os.rename(current_state_scaler_filename, to_state_scaler_filename)

def getMetaData(user_id, state):
    file_name = './output_files/id_' + str(user_id) + '_state_metadata.txt'
    if os.path.exists(file_name):
        with open(file_name, 'rb') as f:
            read_meta_data = pickle.load(f)
            f.close()
            return read_meta_data[state]
    else:
        return {}

def setMetaData(user_id, state, in_meta_data):
    file_name = './output_files/id_' + str(user_id) + '_state_metadata.txt'
    meta_data = {}
    if os.path.exists(file_name):
        with open(file_name, 'rb') as f:
            meta_data = pickle.load(f)
            f.close()
    meta_data[state] = in_meta_data
    with open(file_name, 'wb') as f:
        pickle.dump(state_meta_data, f)
        f.close()
