import server.taints
from server.taints import T_method__, T_scope__
from server.taints import taint_expr__ as T_
from server.taintWrappers import *
import server.staticTaintManager as stm

import numpy as np
import os
from sklearn import preprocessing
import sklearn.linear_model
import pickle

def initialize():
    print("[LOG] initializing stm")
    global STM
    STM = stm.staticTaintManager()

def find_gr_taint(first, second):
    with T_method__('find_gr_taint', [first, second]) as T:
        with T_scope__('if', 1, T) as T:
            if T_(hasattr(first, 'taint'), T):
                ft = T(first).taint
            else:
                ft = None
        with T_scope__('if', 2, T) as T:
            if T_(hasattr(first, 'taint'), T):
                st = T(second).taint
            else:
                st = None
        with T_scope__('if', 3, T) as T:
            if T_(ft == 'HIGH' or st == 'HIGH', T):
                return T('HIGH')
        with T_scope__('if', 4, T) as T:
            if T_(ft == 'LOW' or st == 'LOW', T):
                return T('LOW')
        return T('None')

def copy_file(fd_in, fd_out):
    with T_method__('copy_file', [fd_in, fd_out]) as T:
        inp = T(pickle.load(fd_in))
        T(pickle.dump(inp, fd_out))


def load_data(fd_list):
    with T_method__('load_data', [fd_list]) as T:
        continue_reading = T(True)
        datalist = T([])
        attributes = T(dict())
        with T_scope__('if', 1, T) as T:
            if T_(type(fd_list) != list, T):
                fd_list = T([T(fd_list)])
        with T_scope__('for', 1, T) as T:
            for fd in T_(fd_list, T):
                try:
                    lines = T(fd.readlines())
                    with T_scope__('if', 2, T) as T:
                        if T_(len(lines) == 0, T):
                            continue
                except:
                    continue
                with T_scope__('for', 2, T) as T:
                    for i in T_(range(len(lines)), T):
                        line = T(lines)[T(i)]
                        with T_scope__('if', 3, T) as T:
                            if T_(line[0] == '|', T):
                                break
                        entry = T(line.replace('\n', '').split(', '))
                        with T_scope__('if', 4, T) as T:
                            if T_(len(entry) > 1, T):
                                T(datalist.append(entry))
                with T_scope__('if', 5, T) as T:
                    if T_(len(attributes) == 0, T):
                        attribute_counter = T(0)
                        attribute_lines = T([])
                        with T_scope__('for', 3, T) as T:
                            for j in T_(range(i, len(lines)), T):
                                line = T(lines)[T(j)]
                                T(attribute_lines.append(line))
                                with T_scope__('if', 6, T) as T:
                                    if T_(line[0] == '|', T):
                                        continue
                                with T_scope__('if', 7, T) as T:
                                    if T_(':' not in line, T):
                                        continue
                                l = T(line.replace('.', '').replace('\n',
                                    '').split(': '))
                                column = T(l)[T(0)]
                                a = T(l)[T(1)]
                                a = T(a.split(', '))
                                attributes[column] = T((T(attribute_counter
                                    ), T(a)))
                                attribute_counter += T(1)
                with T_scope__('if', 8, T) as T:
                    if T_(not continue_reading, T):
                        break
                    else:
                        T(print('have read', len(datalist),
                            'entries, continuing...'))
        assert T(T(len(datalist)) > T(0)), T(
            'no data in any of the file descriptors!')
        return T((T(datalist), T(attributes), T(attribute_lines)))

def write_data(fd_list, datalist, attribute_lines):
    with T_method__('write_data', [fd_list, datalist, attribute_lines]) as T:
        writethis = T('\n'.join(T([', '.join(data) for data in datalist])))
        writethis += T(''.join(T(attribute_lines)))
        writethis += T('\n\n')
        rt = T(find_gr_taint(T(datalist), T(attribute_lines)))
        with T_scope__('if', 1, T) as T:
            if T_(type(fd_list) == list or type(fd_list) == tlist, T):
                T(fd_list[0].write(T(writethis)))
                fd_list[0].taint = T(rt)
            else:
                fd_list.write(writethis)
                fd_list.taint = rt


def data_where(fd_list_in, fd_list_out, args):
    with T_method__('data_where', [fd_list_in, fd_list_out, args]) as T:
        data, attributes, attribute_lines = T(load_data(fd_list_in))
        assert T(T(len(args)) == T(2))
        column = T(args)[T(0)]
        value = T(args)[T(1)]
        with T_scope__('if', 1, T) as T:
            if T_(column not in attributes, T):
                raise T(Exception('column %s not available!' % column))
        column_id, column_values = T(attributes)[T(column)]
        with T_scope__('if', 2, T) as T:
            if T_(value not in column_values and column_values[0] !=
                'continuous', T):
                raise T(Exception('invalid value %s for %s' % (value, column)))
        filtered_list = T([])
        with T_scope__('for', 1, T) as T:
            for d in T_(data, T):
                with T_scope__('if', 3, T) as T:
                    if T_(d[column_id] == value, T):
                        T(filtered_list.append(d))
        T(write_data(fd_list_out, filtered_list, attribute_lines))
        fd_list_out[0].taint = T('LOW')


def data_where_multiple(fd_list_in, fd_list_out, args):
    with T_method__('data_where_multiple', [fd_list_in, fd_list_out, args]
        ) as T:
        data, attributes, attribute_lines = T(load_data(fd_list_in))
        assert T(T(len(args)) == T(2))
        all_these = T(args)[T(0)]
        any_these = T(args)[T(1)]
        all_ids = T([])
        with T_scope__('for', 1, T) as T:
            for a in T_(all_these, T):
                column, value = T(a)
                with T_scope__('if', 1, T) as T:
                    if T_(column not in attributes, T):
                        raise T(Exception('column %s not available!' % column))
                column_id, column_values = T(attributes)[T(column)]
                with T_scope__('if', 2, T) as T:
                    if T_(value not in column_values and column_values[0] !=
                        'continuous', T):
                        raise T(Exception('invalid value %s for %s' % (
                            value, column)))
                T(all_ids.append((column_id, value)))
        any_ids = T([])
        with T_scope__('for', 2, T) as T:
            for a in T_(any_these, T):
                column, value = T(a)
                with T_scope__('if', 3, T) as T:
                    if T_(column not in attributes, T):
                        raise T(Exception('column %s not available!' % column))
                column_id, column_values = T(attributes)[T(column)]
                with T_scope__('if', 4, T) as T:
                    if T_(value not in column_values and column_values[0] !=
                        'continuous', T):
                        raise T(Exception('invalid value %s for %s' % (
                            value, column)))
                T(any_ids.append((column_id, value)))
        filtered_list = T([])
        with T_scope__('for', 3, T) as T:
            for d in T_(data, T):
                d_in = T(True)
                with T_scope__('for', 4, T) as T:
                    for column_id, value in T_(all_ids, T):
                        with T_scope__('if', 5, T) as T:
                            if T_(d[column_id] != value, T):
                                d_in = T(False)
                                break
                with T_scope__('if', 6, T) as T:
                    if T_(not d_in, T):
                        continue
                with T_scope__('if', 7, T) as T:
                    if T_(len(any_ids) == 0, T):
                        T(filtered_list.append(d))
                with T_scope__('for', 5, T) as T:
                    for column_id, value in T_(any_ids, T):
                        with T_scope__('if', 8, T) as T:
                            if T_(d[column_id] == value, T):
                                T(filtered_list.append(d))
                                break
        T(write_data(fd_list_out, filtered_list, attribute_lines))


def count_subset(fd_list_in, fd_list_out, args):
    with T_method__('count_subset', [fd_list_in, fd_list_out, args]) as T:
        data, attributes, attribute_lines = T(load_data(fd_list_in))
        count = T(len(data))
        T(fd_list_out[0].write(str(count)))
        with T_scope__('if', 1, T) as T:
            if T_(hasattr(count, 'taint'), T):
                fd_list_out[0].taint = T(count).taint


def apply_dp_to_count(fd_list_in, fd_list_out, args):
    with T_method__('apply_dp_to_count', [fd_list_in, fd_list_out, args]) as T:
        lines = T([])
        with T_scope__('for', 1, T) as T:
            for fd in T_(fd_list_in, T):
                try:
                    lines = T(fd.readlines())
                    break
                except:
                    continue
        assert T(T(len(lines)) > T(0)), T('no data in any file!')
        clean_answer = T(int(lines[0].replace('\n', '')))
        sensitivity = T(1)
        assert T(T(len(args)) == T(2))
        epsilon = T(args)[T(0)]
        rand = T(args)[T(1)]
        T(np.random.seed(rand))
        l = T(T(sensitivity) / T(epsilon))
        noise = T(np.random.laplace(loc=0.0, scale=l, size=1))[T(0)]
        public_answer = T(round(clean_answer + noise, 0))
        T(fd_list_out[0].write(str(public_answer)))
        fd_list_out[0].taint = T('LOW')

def convert_attributes(attribute_map, data_elem):
    with T_method__('convert_attributes', [attribute_map, data_elem]) as T:
        d_enc = T([])
        with T_scope__('for', 1, T) as T:
            for a_id in T_(range(len(data_elem) - 1), T):
                with T_scope__('if', 1, T) as T:
                    if T_(data_elem[a_id] == '?', T):
                        return T([])
                with T_scope__('if', 2, T) as T:
                    if T_(a_id not in attribute_map, T):
                        T(d_enc.append(float(data_elem[a_id])))
                    else:
                        with T_scope__('if', 3, T) as T:
                            if T_(a_id in attribute_map and attribute_map[
                                a_id] is not None, T):
                                T(d_enc.append(float(attribute_map[a_id][
                                    data_elem[a_id]])))
        return T(d_enc)


def make_train_test(datalist, attribute_map, train_factor):
    with T_method__('make_train_test', [datalist, attribute_map, train_factor]
        ) as T:
        X_all = T([])
        Y_all = T([])
        with T_scope__('for', 1, T) as T:
            for d in T_(datalist, T):
                d_enc = T(convert_attributes(attribute_map, d))
                with T_scope__('if', 1, T) as T:
                    if T_(len(d_enc) > 0, T):
                        T(X_all.append(np.array(d_enc)))
                        with T_scope__('if', 2, T) as T:
                            if T_(d[-1] == '<=50K', T):
                                T(Y_all.append(0))
                            else:
                                T(Y_all.append(1))
        X_all = T(tndarray(np.array(X_all), STM.get_taints("numpy.array", X_all.taint if hasattr(Y_all, 'taint') else None)))
        Y_all = T(tndarray(np.array(Y_all), STM.get_taints("numpy.array", X_all.taint if hasattr(Y_all, 'taint') else None)))
        ids = T([i for i in range(len(X_all))])

        T(np.random.shuffle(ids))
        with T_scope__('if', 3, T) as T:
            if T_(train_factor is not None, T):
                split = T(int(train_factor * len(X_all)))
                ids_train = T(ids)[:T(split)]
                ids_test = T(ids)[T(split):]
                return T((T(X_all)[T(ids_train)], T(Y_all)[T(ids_train)], T
                    (X_all)[T(ids_test)], T(Y_all)[T(ids_test)]))
            else:
                return T((T(None), T(None), T(X_all), T(Y_all)))


def learn(X_train, Y_train, X_test, Y_test, C, random_state, outspec):
    with T_method__('learn', [X_train, Y_train, X_test, Y_test, C,
        random_state, outspec]) as T:
        clf = T(tLogisticRegression(sklearn.linear_model.LogisticRegression(random_state=42, C=C), STM.get_taints("LogisticRegression", C.taint if hasattr(C, 'taint') else None)))
        T(clf.fit(X_train, Y_train))
        acc = T(clf.score(X_test, Y_test))
        fd_out, datalist, attribute_lines, fd_model, fd_acc = T(outspec)
        T(write_data(fd_out, datalist, attribute_lines))
        T(pickle.dump(clf.obj, fd_model))
        T(fd_acc.write(str(acc)))
        fd_acc.taint = T('LOW')

        return T((T(fd_acc), T(fd_model), T(fd_out)))


def learn_scaled(X_train, Y_train, X_test, Y_test, C, random_state, outspec):
    with T_method__('learn_scaled', [X_train, Y_train, X_test, Y_test, C,
        random_state, outspec]) as T:
        scaler = T(tStandardScaler(preprocessing.StandardScaler().fit(X_train), STM.get_taints("preprocessing.StandardScaler.fit", X_train.taint if hasattr(X_train, 'taint') else None)))
        clf = T(tLogisticRegression(sklearn.linear_model.LogisticRegression(random_state=42, C=C), STM.get_taints("LogisticRegression", C.taint if hasattr(C, 'taint') else None)))
        T(clf.fit(scaler.transform(X_train), Y_train))

        acc = T(clf.score(scaler.transform(X_test), Y_test))
        fd_out, datalist, attribute_lines, fd_model, fd_scaler, fd_acc = T(
            outspec)
        T(write_data(fd_out, datalist, attribute_lines))
        T(pickle.dump(clf.obj, fd_model))
        fd_model.taint = clf.taint
        T(pickle.dump(scaler.obj, fd_scaler))
        T(fd_acc.write(str(acc)))
        return T((T(fd_acc), T(fd_model), T(fd_out)))


def exclude_coef(clf, attribute_map, attributes, howmany):
    with T_method__('exclude_coef', [clf, attribute_map, attributes, howmany]
        ) as T:
        attribute_map_reduced = T(dict(attribute_map))
        coef = T(clf).coef_[T(0)]
        coef = T(list(zip(coef, [i for i in range(len(coef))])))
        T(coef.sort(key=lambda x: abs(x[0])))
        coef_explained = T([])
        with T_scope__('for', 1, T) as T:
            for i in T_(range(len(coef)), T):
                coef_id = T(coef)[T(i)][T(1)]
                with T_scope__('for', 2, T) as T:
                    for a in T_(attributes, T):
                        with T_scope__('if', 1, T) as T:
                            if T_(attributes[a][0] == coef_id, T):
                                attribute_name = T(a)
                                break
                T(coef_explained.append([attribute_name, coef_id, coef[i][0]]))
        T(print('psst, the coefficients are just given for testing...',
            coef_explained))
        with T_scope__('for', 3, T) as T:
            for i in T_(range(howmany), T):
                a_id = T(coef_explained)[T(i)][T(1)]
                attribute_map_reduced[a_id] = T(None)
        return T(attribute_map_reduced)


def load_and_encode_data(fd_list_in):
    with T_method__('load_and_encode_data', [fd_list_in]) as T:
        datalist, attributes, attribute_lines = T(load_data(fd_list_in))
        attribute_map = T(dict())
        with T_scope__('for', 1, T) as T:
            for a in T_(attributes, T):
                a_id, values = T(attributes)[T(a)]
                with T_scope__('if', 1, T) as T:
                    if T_(values[0] == 'continuous', T):
                        continue
                attribute_map[a_id] = T(dict())
                with T_scope__('for', 2, T) as T:
                    for i in T_(range(len(values)), T):
                        attribute_map[a_id][values[i]] = T(float(i))
        return T((T(datalist), T(attributes), T(attribute_lines), T(
            attribute_map)))


def logistic_regression_step(fd_list_in, fd_model_in, fds_out,
    train_test_split, C, exclude_this_much, rand):
    with T_method__('logistic_regression_step', [fd_list_in, fd_model_in,
        fds_out, train_test_split, C, exclude_this_much, rand]) as T:
        fd_out, fd_model, fd_scaler, fd_acc = T(fds_out)
        datalist, attributes, attribute_lines, attribute_map = T(
            load_and_encode_data(fd_list_in))
        with T_scope__('if', 1, T) as T:
            if T_(exclude_this_much != None, T):
                clf = T(pickle.load(fd_model_in))
                attribute_map = T(exclude_coef(clf, attribute_map,
                    attributes, exclude_this_much))
        X_train, Y_train, X_test, Y_test = T(make_train_test(datalist,
            attribute_map, train_test_split))
        outspec = T((T(fd_out), T(datalist), T(attribute_lines), T(fd_model
            ), T(fd_scaler), T(fd_acc)))
        fd_acc, fd_model, fd_out = T(learn_scaled(X_train, Y_train, X_test,
            Y_test, 1.0, rand, outspec))


def logistic_regression_test(fd_list_in, fd_model_in, fd_scaler_in, fd_acc,
    exclude_this_much):
    with T_method__('logistic_regression_test', [fd_list_in, fd_model_in,
        fd_scaler_in, fd_acc, exclude_this_much]) as T:
        T(print('[LOG] A1'))
        clf = T(pickle.load(fd_model_in))
        T(print('[LOG] A2'))
        scaler = T(pickle.load(fd_scaler_in))
        T(print('[LOG] A3'))
        datalist, attributes, attribute_lines, attribute_map = T(
            load_and_encode_data(fd_list_in))
        T(print('[LOG] A4'))
        with T_scope__('if', 1, T) as T:
            if T_(exclude_this_much != None, T):
                clf = T(pickle.load(fd_model_in))
                attribute_map = T(exclude_coef(clf, attribute_map,
                    attributes, exclude_this_much))
        T(print('[LOG] A5'))
        _, _, X_test, Y_test = T(make_train_test(datalist, attribute_map, None)
            )
        acc = T(clf.score(scaler.transform(X_test), Y_test))
        T(fd_acc.write(str(acc)))


def act_11_learn(params, fds_in, fds_out, meta_data):
    with T_method__('act_11_learn', [params, fds_in, fds_out]) as T:
        train_test_split = T(params)[T('train_test_split')]
        rand = T(params)[T('rand')]
        C = T(params)[T('C')]
        assert T(T(T(type(train_test_split)) == T(float)) and T(T(0) < T(
            train_test_split) < T(1)))
        assert T(T(type(rand)) == T(int))
        assert T(T(T(type(C)) == T(float)) and T(T(C) > T(0)))
        T(np.random.seed(rand))
        fds_output = T((T(fds_out)[T('data')], T(fds_out)[T('model')], T(
            fds_out)[T('scaler')], T(fds_out)[T('acc')]))
        T(logistic_regression_step(fds_in['raw-data'], None, fds_output,
            train_test_split, C, None, rand))
        return T((T(True), T('')))


def act_12_regularize(params, fds_in, fds_out, meta_data):
    with T_method__('act_12_regularize', [params, fds_in, fds_out, meta_data]) as T:
        train_test_split = T(params)[T('train_test_split')]
        rand = T(params)[T('rand')]
        C = T(params)[T('C')]
        assert T(T(T(type(train_test_split)) == T(float)) and T(T(0) < T(
            train_test_split) < T(1)))
        assert T(T(type(rand)) == T(int))
        assert T(T(T(type(C)) == T(float)) and T(T(C) > T(0)))
        fds_out = T((T(fds_out)[T('data')], T(fds_out)[T('model')], T(
            fds_out)[T('scaler')], T(fds_out)[T('acc')]))
        T(logistic_regression_step([fds_in['data']], fds_in['model'],
            fds_out, train_test_split, C, None, rand))
        return T((T(True), T('')))


def act_13_exclude_coef(params, fds_in, fds_out, meta_data):
    with T_method__('act_13_exclude_coef', [params, fds_in, fds_out, meta_data]) as T:
        train_test_split = T(params)[T('train_test_split')]
        rand = T(params)[T('rand')]
        C = T(params)[T('C')]
        exclude_this_much = T(params)[T('exclude_this_much')]
        assert T(T(T(type(train_test_split)) == T(float)) and T(T(0) < T(
            train_test_split) < T(1)))
        assert T(T(type(rand)) == T(int))
        assert T(T(T(type(C)) == T(float)) and T(T(C) > T(0)))
        assert T(T(T(type(exclude_this_much)) == T(int)) and T(T(
            exclude_this_much) > T(0)))
        fds_out = T((T(fds_out)[T('data')], T(fds_out)[T('model')], T(
            fds_out)[T('scaler')], T(fds_out)[T('acc')]))
        T(logistic_regression_step([fds_in['data']], fds_in['model'],
            fds_out, train_test_split, C, exclude_this_much, rand))
        return T((T(True), T('')))


def act_21_subset(params, fds_in, fds_out, meta_data):
    with T_method__('act_21_subset', [params, fds_in, fds_out]) as T:

        with T_scope__('if', 1, T) as T:
            if T_('column' in params and 'value' in params, T):
                column = T(params)[T('column')]
                value = T(params)[T('value')]
                assert T(T(type(column)) == T(str))
                assert T(T(type(value)) == T(str))
                with T_scope__('if', 2, T) as T:
                    if T_('raw-data' in fds_in, T):
                        T(data_where(fds_in['raw-data'], [fds_out['data']],
                            [column, value]))
                    else:
                        T(data_where(fds_in['data'], [fds_out['data']], [
                            column, value]))
                if 'model' in fds_in:
                    copy_file(fds_in['model'], fds_out['model'])
                    copy_file(fds_in['scaler'], fds_out['scaler'])
                return T((T(True), T('')))
            else:
                with T_scope__('if', 3, T) as T:
                    if T_('all_these' in params and 'any_these' in params, T):
                        all_these = T(params)[T('all_these')]
                        any_these = T(params)[T('any_these')]
                        assert T(T(type(all_these)) == T(list))
                        assert T(T(type(any_these)) == T(list))
                        with T_scope__('if', 4, T) as T:
                            if T_(len(all_these) > 0, T):
                                c, v = T(all_these)[T(0)]
                                assert T(T(type(c)) == T(str))
                                assert T(T(type(v)) == T(str))
                        with T_scope__('if', 5, T) as T:
                            if T_(len(any_these) > 0, T):
                                c, v = T(any_these)[T(0)]
                                assert T(T(type(c)) == T(str))
                                assert T(T(type(v)) == T(str))
                        with T_scope__('if', 6, T) as T:
                            if T_('raw-data' in fds_in, T):
                                T(data_where_multiple(fds_in['raw-data'], [
                                    fds_out['data']], [all_these, any_these]))
                            else:
                                T(data_where_multiple(fds_in['data'], [
                                    fds_out['data']], [all_these, any_these]))
                        if 'model' in fds_in:
                            copy_file(fds_in['model'], fds_out['model'])
                            copy_file(fds_in['scaler'], fds_out['scaler'])
                        return T((T(True), T('')))
                    else:
                        raise T(Exception('parameters not found!'))


def act_22_count(params, fds_in, fds_out, meta_data):
    with T_method__('act_22_count', [params, fds_in, fds_out, meta_data]) as T:
        T(count_subset([fds_in['data']], [fds_out['data']], []))
        return T((T(True), T('')))


def act_23_noise_and_release(params, fds_in, fds_out, meta_data):
    with T_method__('act_23_noise_and_release', [params, fds_in, fds_out, meta_data]
        ) as T:
        epsilon = T(params)[T('epsilon')]
        randomness = T(params)[T('randomness')]
        with T_scope__('if', 1, T) as T:
            if T_(not type(epsilon) == float, T):
                return T((T(False), T('error in epsilon type')))
        with T_scope__('if', 2, T) as T:
            if T_(not 0 < epsilon < 100, T):
                return T((T(False), T('error in epsilon range')))
        with T_scope__('if', 3, T) as T:
            if T_(not type(randomness) == int, T):
                return T((T(False), T('error in randomness type')))
        T(apply_dp_to_count([fds_in['data']], [fds_out['data']], [epsilon,
            randomness]))
        return T((T(True), T('')))


def act_24_learn(params, fds_in, fds_out, meta_data):
    with T_method__('act_24_learn', [params, fds_in, fds_out, meta_data]) as T:
        train_test_split = T(params)[T('train_test_split')]
        rand = T(params)[T('rand')]
        C = T(params)[T('C')]
        assert T(T(T(type(train_test_split)) == T(float)) and T(T(0) < T(
            train_test_split) < T(1)))
        assert T(T(type(rand)) == T(int))
        assert T(T(T(type(C)) == T(float)) and T(T(C) > T(0)))
        T(np.random.seed(rand))
        T(print('C', C))
        fds_out = T((T(fds_out)[T('data')], T(fds_out)[T('model')], T(
            fds_out)[T('scaler')], T(fds_out)[T('acc')]))
        T(logistic_regression_step([fds_in['data']], None, fds_out,
            train_test_split, C, None, rand))
        return T((T(True), T('')))


def act_25_subset(params, fds_in, fds_out, meta_data):
    with T_method__('act_25_subset', [params, fds_in, fds_out, meta_data]) as T:
        column = T(params)[T('column')]
        value = T(params)[T('value')]
        assert T(T(type(column)) == T(str))
        assert T(T(type(value)) == T(str))
        T(data_where([fds_in['data']], [fds_out['data']], [column, value]))
        return T((T(True), T('')))


def act_26_test(params, fds_in, fds_out, meta_data):
    with T_method__('act_26_test', [params, fds_in, fds_out, meta_data]) as T:
        T(logistic_regression_test([fds_in['data']], fds_in['model'],
            fds_in['scaler'], fds_out['acc'], None))
        return T((T(True), T('')))


def finish(params, fd_in, fds_out, meta_data):
    with T_method__('finish', [params, fd_in, fds_out, meta_data]) as T:
        return T((T(True), T('')))

initialize()
