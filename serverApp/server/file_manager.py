import os
import os.path
import pycapsicum as p
import server.helper as hlp
from server.taintWrappers import *
from flask import session

AT_FDCWD = -100

def prepare_raw_input_files():
    fd_list = []
    # make a new CapRights, set to CAP_READ
    b = p.CapRights(['CAP_READ'])

    if(('rawfiles' not in session)):
          raise Exception("please select raw data files beforehand")

    for root, dirs, files in os.walk("./raw_data"):
        for filename in files:
            if(filename in session['rawfiles']):
                fd = p.openat(AT_FDCWD, root+ "/" + filename, 'rw')
                b.limit(fd)
                fd_in = tTextIOWrapper(fd, 'HIGH')
                fd_list.append(fd_in)


    return fd_list

def prepare_input_files(user_id, current_state, need_raw_data):
    try:
        fds_in = dict()
        fds_in['raw-data'] = None
        if current_state == 0 or need_raw_data:
            fds_in['raw-data'] = prepare_raw_input_files()
        input_exists = False
        prefix = './output_files/id_' + str(user_id) + '_state_' + str(current_state)
        acc_filename = prefix + '_acc'
        model_filename = prefix + '_model'
        data_filename = prefix + '_data'
        scaler_filename = prefix + '_scaler'

        if current_state != 0 or (current_state == 0 and os.path.exists(acc_filename))   :
            input_exists = True

        if input_exists:
            returnState, taints = hlp.getSateStateTaintsInFile(user_id, current_state)
            acc_taint, model_taint, data_taint, scaler_taint = taints

            print("[LOG][prepare_input_files] ", "acc file ", acc_filename)
            fd_acc = p.open( acc_filename, 'rw')
            accHdlr = os.fdopen(fd_acc, "r+")
            # create a new CapRights object
            b = p.CapRights(['CAP_READ'])
            # set those capabilites to x
            b.limit(accHdlr)
            accHdlr_in = tTextIOWrapper(accHdlr, acc_taint)
            fds_in['acc'] = accHdlr_in

            fd_model = p.open(model_filename, 'rw')
            modelHdlr = os.fdopen(fd_model, "rb")
            # set those capabilites
            b.limit(modelHdlr)
            modelHdlr_in = tTextIOWrapper(modelHdlr, model_taint)
            fds_in['model'] = modelHdlr_in

            fd_data = p.open(data_filename , 'rw')
            dataHdlr = os.fdopen(fd_data, "r+")
            b.limit(dataHdlr)
            dataHdlr_in = tTextIOWrapper(dataHdlr, data_taint)
            fds_in['data'] = dataHdlr_in

            fd_scaler = p.open(scaler_filename, 'rw')
            scalerHdlr = os.fdopen(fd_scaler, "rb")
            # set those capabilites
            b.limit(scalerHdlr)
            scalerHdlr_in = tTextIOWrapper(scalerHdlr, scaler_taint)
            fds_in['scaler'] = scalerHdlr_in

        return fds_in

    except Exception as e:
            print("there was an error in preparing input - "+ str(e))


def prepare_output_file(user_id, to_state):

    fds_out = dict()

    try:
        prefix = './output_files/id_' + str(user_id) + '_state_' + str(to_state)
        fd_acc = p.open( prefix  + '_acc', 'rwc')
        accHdlr = os.fdopen(fd_acc, "w+")
        #empty the file if it is not the first time the user call for this state
        accHdlr.truncate()
        # create a new CapRights object
        b = p.CapRights(['CAP_WRITE'])
        # set those capabilites to x
        b.limit(accHdlr)
        accHdlr_out = tTextIOWrapper(accHdlr, 'None')
        fds_out['acc'] = accHdlr_out

        fd_model = p.open( prefix + '_model', 'rwc')
        modelHdlr = os.fdopen(fd_model, "wb")
        #empty the file if it is not the first time the user call for this state
        modelHdlr.truncate()
        # set those capabilites
        b.limit(modelHdlr)
        modelHdlr_out = tBufferedWriter(modelHdlr, 'None')
        fds_out['model'] = modelHdlr_out

        fd_data = p.open( prefix + '_data', 'rwc')
        dataHdlr = os.fdopen(fd_data, "w+")
        #empty the file if it is not the first time the user call for this state
        dataHdlr.truncate()
        b.limit(dataHdlr)
        dataHdlr_out = tTextIOWrapper(dataHdlr, 'None')
        fds_out['data'] = dataHdlr_out

        fd_scaler = p.open( prefix + '_scaler', 'rwc')
        scalerHdlr = os.fdopen(fd_scaler, "wb")
        #empty the file if it is not the first time the user call for this state
        scalerHdlr.truncate()
        # set those capabilites
        b.limit(scalerHdlr)
        scalerHdlr_out = tBufferedWriter(scalerHdlr, 'None')
        fds_out['scaler'] = scalerHdlr_out

        return fds_out

    except Exception as e:
        print("there was an error in preparing output - "+ str(e))
