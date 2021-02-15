from server import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    firstname = db.Column(db.String(50), unique=True, nullable=False)
    lastname = db.Column(db.String(60), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    state = db.relationship('State', backref='user_ref', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


class State(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    current_state = db.Column(db.Integer, default=0, nullable=False)
    acc_taint = db.Column(db.String(60), nullable=False)
    model_taint = db.Column(db.String(60), nullable=False)
    data_taint = db.Column(db.String(60), nullable=False)
    scaler_taint = db.Column(db.String(60), nullable=False)
    

    def __repr__(self):
        return f"State('{self.user_id}', '{self.current_state}', acc_taint = '{self.acc_taint}', model_taint = '{self.model_taint}', data_taint = '{self.data_taint}', scaler_taint = '{self.scaler_taint}' )"
        
 
class Action_capability(db.Model):
     id = db.Column(db.Integer, primary_key=True)
     capability = db.Column(db.String(512), nullable=False)
     properties = db.Column(db.Integer, default=0, nullable=False)
     parent = db.Column(db.Integer, nullable=True)
     first_child = db.Column(db.Integer, nullable=True)
     last_child = db.Column(db.Integer, nullable=True)
     left_sibling = db.Column(db.Integer, nullable=True)
     right_sibling = db.Column(db.Integer, nullable=True)
     
     def __repr__(self):
        return f"Capability('{self.id}', capabilities = '{self.capability}', properties = '{self.properties}', parent = '{self.parent}', first_child  = '{self.first_child }', last_child = '{self.last_child}',  right_sibling = '{self.right_sibling}', left_sibling = '{self.left_sibling}')"
     
