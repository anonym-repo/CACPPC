import pycapsicum as p
import os
import os.path
import algorithms.adult_lib as al
from server import server
from server.models import State
import server.helper as hlp
import server.file_manager as fm
from server.taintWrappers import *
from flask import session
import cProfile, pstats, io
from pstats import SortKey
from termcolor import colored


def entry(dispatcher_conn, params, user_id, current_state,
          to_state, action_name,
          need_raw_data, do_sandboxing=True):

    tmp_to_states = str(to_state)
    if current_state == to_state:
        tmp_to_states += "_tmp"

    try:

        if(action_name != 'None' and action_name != 'TRANSFER'):
            fds_in = fm.prepare_input_files(user_id, current_state, need_raw_data)
            fds_out = fm.prepare_output_file(user_id, tmp_to_states)
            if do_sandboxing:
                #enter capability mode
                p.enter()

            metadata = []

            action_to_call = getattr(al, action_name)
            #pr = cProfile.Profile()
            #pr.enable()
            returnValue, returnMsg = action_to_call(params, fds_in, fds_out, metadata)
            #pr.disable()
            #s = io.StringIO()
            #sortby = SortKey.CUMULATIVE
            #ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
            #ps.print_stats()
            #print(colored("[LOG][Dispatcher][Time]["+ action_name+ "]\n", 'red'), s.getvalue())

            if returnValue == True:
                taints = fds_out['acc'].taint, fds_out['model'].taint, fds_out['data'].taint, fds_out['scaler'].taint
                dispatcher_conn.send("Done")
                dispatcher_conn.send(taints)
            else:
                dispatcher_conn.send("Error: " + returnMsg)
        else:
            dispatcher_conn.send("Done")
            taints = []
            dispatcher_conn.send(taints)
        dispatcher_conn.close()

    except Exception as e:
        dispatcher_conn.send(e)
        dispatcher_conn.close()
