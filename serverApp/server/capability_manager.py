
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes
from flask_login import  current_user
import server.helper as hlp
from server.models import Action_capability
from server import server, db

key = b'very secret key_'
delima = ";;;"
init_properties = 1
revoked_subproperty = 16
disabled_subproperty = 8

def get_action_capability(entry_id):
    cap = Action_capability.query.filter_by(id=entry_id).first()
    return cap


def encrypt(data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(bytes(data, 'utf-8'))
    return {
        'ciphertext': b64encode(ciphertext).decode('utf-8'),
        'nonce': b64encode(cipher.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }

def decrypt(user_capability):
    cap_split = user_capability.split(delima)
    ciphertext = b64decode(cap_split[0])
    nonce = b64decode(cap_split[1])
    tag = b64decode(cap_split[2])
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def check_capability(filename, target_cap):
     f = open("./cap_folder/"+filename, "r")
     user_capability = f.read()
     plain_txt = decrypt(user_capability)
     split_data = bytes.decode(plain_txt).split(";")
     user_id = split_data[0].split('=')[1]

     if(not(hlp.is_int(user_id)) or not(( int(user_id) == current_user.id))):
         return False
     entry_id = split_data[1].split('=')[1]
     act_cap = get_action_capability(entry_id)
     caps = act_cap.capability.split(';')

     for cap in caps:
     	c = cap.split('=')
     	if(len(c) > 1 and c[1] == target_cap):
     	    return True

     return False


def create_action_capability(capabilities, properties):
    action_cap = Action_capability(capability = capabilities, properties = properties)
    db.session.add(action_cap)
    db.session.commit()
    return action_cap.id


def delegate(action_cap_id, user_id, capabilities, properties = init_properties):
    new_id = create_action_capability(capabilities, properties)
    new_cap = Action_capability.query.filter_by(id=new_id).first()
    act_cap = Action_capability.query.filter_by(id=action_cap_id).first()
    new_cap.parent = action_cap_id
    pre_last_child_id = act_cap.last_child

    if(pre_last_child_id == None):             # it is the first delegated child
        act_cap.first_child = new_id
    else:                                      # insert new delgated capbility at the end of the list
        Prev_Last_Child = Action_capability.query.filter_by(id=pre_last_child_id).first()
        act_cap.last_child = new_id
        Prev_Last_Child.right_sibling = new_id
        new_cap.left_sibling = pre_last_child_id

    act_cap.last_child = new_id
    db.session.commit()

def revoke_capability(act_cap_id):
    revoked_cap = Action_capability.query.filter_by(id=act_cap_id).first()
    parent = Action_capability.query.filter_by(id=revoked_cap.parent).first()

    if(parent == None):
        return

    if(parent.first_child == parent.last_child): # it is the only delegated capability
       parent.first_child = None
       parent.last_child = None
    elif(parent.first_child == int(act_cap_id)):
       parent.first_child = revoked_cap.right_sibling
       prev_rs = Action_capability.query.filter_by(id=revoked_cap.right_sibling).first()
       prev_rs.left_sibling = None
    elif(parent.last_child == int(act_cap_id)):
       parent.last_child = revoked_cap.left_sibling
       prev_ls = Action_capability.query.filter_by(id=revoked_cap.left_sibling).first()
       prev_ls.right_sibling = None
    else:                                        #the revoked capability is in the middle of the delegated capabilities' list
       prev_ls = Action_capability.query.filter_by(id=revoked_cap.left_sibling).first()
       prev_rs = Action_capability.query.filter_by(id=revoked_cap.right_sibling).first()
       prev_ls.right_sibling = prev_rs
       prev_rs.left_sibling = prev_ls

    revoked_cap.properties |= revoked_subproperty #mark the revoked capability
    db.session.commit()


def disable_capability(act_cap_id):
    disabled_cap = Action_capability.query.filter_by(id=act_cap_id).first()
    disabled_cap.properties |= revoked_subproperty #mark the revoked capability
    db.session.commit()


def get_child_caps(cap_file):
    child_caps = []
    if True: #('cap_file' in session):
        #filename = session['cap_file']
        f = open("./cap_folder/" + cap_file, "r")
        user_capability = f.read()
        plain_txt = decrypt(user_capability)
        split_data = bytes.decode(plain_txt).split(";")
        user_id = split_data[0].split('=')[1]

        if(not(hlp.is_int(user_id)) or not(( int(user_id) == current_user.id))):
           raise Exception("wrong uploaded capability")

        act_cap_id = split_data[1].split('=')[1]
        act_cap = Action_capability.query.filter_by(id=act_cap_id).first()

        next_child_id = act_cap.first_child
        while( not(next_child_id == None)): # there is at least one delegated capability
            c_cap = Action_capability.query.filter_by(id=next_child_id).first()
            if ((c_cap.properties & revoked_subproperty)  == 0): #select childs which are not revoked
                child_caps.append(c_cap)
            next_child_id = c_cap.right_sibling

    return child_caps


def listAll():
    caps = Action_capability.query.all()
    return caps
