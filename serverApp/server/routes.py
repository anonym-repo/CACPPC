from multiprocessing import Process, Pipe
import server.helper as hlp
from flask import redirect, url_for, request, render_template, flash, session
from server import server, db, bcrypt, state_machine
from server.forms import LoginForm, UpdateCapability
from server.models import User, State, Action_capability
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename
import os
import server.policy_enforcer as pe
import server.capability_manager as cm


@server.route('/', methods=['GET', 'POST'])
@server.route('/home', methods=['GET', 'POST'])
def home():
    if  current_user.is_authenticated:
        current_state = hlp.get_current_state()
        current_taint = hlp.get_all_taints()
        state_name = state_machine.get_state_name(int(current_state))

    if request.method == 'POST':
        try:
            pe.processActionRequest(request.form)
        except Exception as e:
            flash("there was an error in procesing of the request - "+ str(e) , 'danger')

        return redirect(url_for('home'))

    else:
        if not  current_user.is_authenticated:
           return render_template('index.html', title = "home")

        actions = hlp.filter_actions_by_caps( state_machine.get_actions_at(current_state))
        return render_template('index.html',
                               title = 'home',
                               current_state = current_state,
                               current_taint = current_taint,
                               state_name=state_name,
                               actions=actions)

@server.route('/reset')
def reset():
    if current_user.is_authenticated:
        hlp.reset_state()

    return redirect(url_for('home'))


@server.route('/login', methods=['GET', 'POST'])
def login():

    if  current_user.is_authenticated:
        flash('You already logged in!', 'success')
        return redirect(url_for('home'))

    loginForm = LoginForm()

    if loginForm.validate_on_submit():
        user = User.query.filter_by(email=loginForm.email.data).first()
        if user and bcrypt.check_password_hash(user.password, loginForm.password.data):
            login_user(user, remember=loginForm.remember.data)
            flash('Welcome  ' + user.firstname + '!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template("login.html", title='login', form=loginForm)

@server.route("/selectrawdata", methods=['GET', 'POST'])
def selectrawdata():

    if request.method == 'POST':
        selected_files = request.form.getlist('rawfiles')
        session['rawfiles'] = selected_files
        return redirect(url_for('home'))
    else:
        fileList = hlp.select_raw_data('HIGH')
        return render_template("selectrawdata.html", title='Select Raw Data', files=fileList)

@server.route("/showdata")
def showdata():

    if not current_user.is_authenticated:
         flash('Please Login first', 'danger')
         return redirect(url_for('login'))

    current_state = hlp.get_current_state()
    content = ""
    if not current_state == 0:
        file_path = "output_files/id_" + str(current_user.id) + "_state_" + str(current_state) + "_data"
        with open(file_path, 'r') as f:
            content = f.read()
    else:
        flash('Raw data cannot be shown', 'danger')

    return  render_template("showdata.html", title='Show Data', text=content)

@server.route('/capmanage', methods=['GET', 'POST'])
@server.route("/capmanage")
def capmanage():
    child_caps = []
    try:
        if('cap_file' in session):
            child_caps = cm.get_child_caps(session['cap_file'])
            if request.method == 'POST':
                 cm.revoke_capability(request.form.get('rev'))
                 return redirect(url_for('capmanage'))
            else:
                 pass
    except Exception as e:
            flash("there was an error in procesing of the request - "+ str(e) , 'danger')

    return  render_template("capmanage.html", title='Capability Management', c_caps = child_caps)

@server.route("/logout")
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))


@server.route("/account", methods=['GET', 'POST'])
def account():

    capForm = UpdateCapability()
    if not current_user.is_authenticated:
         flash('Please Login first', 'danger')
         return redirect(url_for('login'))

    if capForm.validate_on_submit():
        cap = capForm.capability.data
        cap_filename = str(current_user.id) + "_" + secure_filename(cap.filename)
        session['cap_file'] = cap_filename
        
        cap.save(os.path.join(server.config['CAP_FOLDER'], cap_filename))
        flash('Your capabilities are updated successfully!', 'success')
        return redirect(url_for('account'))

    return render_template("account.html", title='account', form=capForm)
