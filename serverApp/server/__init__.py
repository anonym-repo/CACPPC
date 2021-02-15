from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

import server.stateMachine as sm

CAP_FOLDER = './cap_folder'

server = Flask(__name__)
Bootstrap(server)

server.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
server.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
server.config['CAP_FOLDER'] = CAP_FOLDER

db = SQLAlchemy(server)
bcrypt = Bcrypt(server)
login_manager = LoginManager(server)
login_manager.login_message_category = 'info'

state_machine = sm.fsm()
state_machine.load('fsmDesc.txt')



from server import routes
