from multiprocessing import Process, Pipe
import server.helper as hlp
from flask import request, session
from server import server, db, bcrypt, state_machine
import server.dispatcher as dispatcher
from flask_login import current_user
import server.capability_manager as cm

def processActionRequest(form):

    if  current_user.is_authenticated:
        current_state = hlp.get_current_state()
        current_taint = hlp.get_all_taints()
        state_name = state_machine.get_state_name(int(current_state))
    else:
        raise Exception("User is not authenticated")


    params, errors = hlp.extract_params(form)

    if errors:
        for err in errors:
            flash(err, 'danger')
    else:
        try:
            if('cap_file' not in session):
                raise Exception("please upload a capability beforehand")
            act_name = form.get('action')
            action = state_machine.get_action_by_name_at(current_state, act_name)

            if(not cm.check_capability(session['cap_file'], action.alias)):
                raise Exception("no appropriate cap has been found")
            to_state = action.get_to_state()
            need_raw_data = action.need_raw_data_input()

            if((current_state == 0 or need_raw_data) and ('rawfiles' not in session)):
                raise Exception("please select raw data files beforehand")


            server_conn, dispatcher_conn = Pipe()
            prc = Process(target=dispatcher.entry,
            args=(dispatcher_conn, params, current_user.id, current_state,
                      to_state, act_name, need_raw_data, hlp, ))
            prc.start()
            dispatcher_error = False
            msg =  server_conn.recv()
            if not msg == "Done":
                dispatcher_error = True

            if not dispatcher_error:
                msg =  server_conn.recv()
                if act_name == 'None':
                    returnState, taints = hlp.getSateStateTaintsInFile(current_user.id, to_state)
                    new_acc, new_model, new_data, new_scaler = taints
                elif act_name == 'TRANSFER':
                    returnState, taints = hlp.getSateStateTaintsInFile(current_user.id, current_state)
                    hlp.updateStateTaintsInFile(current_user.id, to_state, taints)
                    new_acc, new_model, new_data, new_scaler = taints
                    hlp.transfer_files(current_user.id, current_state, to_state)
                else:
                    hlp.updateStateTaintsInFile(current_user.id, to_state, msg)
                    new_acc, new_model, new_data, new_scaler = msg
                    if current_state == to_state:
                        hlp.correct_tmp_filenames(current_user.id, to_state)

            prc.join()

            if not dispatcher_error:
               hlp.set_user_state(to_state)
        except Exception as e:
            raise Exception(str(e))
