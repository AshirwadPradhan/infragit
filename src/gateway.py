# The GATEWAY for the client (entry point to the application)
from flask import Flask, request
from localdb import IGDB
import hashlib
import os
from datetime import datetime
from Crypto.Random import get_random_bytes
import base64

SECRET_MESSAGE = 'very secret'
app = Flask(__name__)

@app.route('/')
def get_secret_message():
    return SECRET_MESSAGE

@app.route('/send_random', methods=['POST'])
def get_client_random():
    pass

@app.route('/register', methods=['POST'])
def resgister_client():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password']

        #Preparing salt
        rand_bytes = get_random_bytes(16)
        b64_salt = base64.b64encode(rand_bytes)
        salt = b64_salt.decode('utf-8')
        # print(salt)

        hashed_username = hashlib.sha256()
        hashed_username.update(username.encode('utf-8'))
        hashusr = hashed_username.hexdigest()

        igdb_users = IGDB(os.path.join('dbs','users.json'))

        if igdb_users.getd(hashusr) is None:

            hashed_p = hashlib.sha256()
            hashed_p.update(password.encode('utf-8'))
            hashed_p.update(salt.encode('utf-8'))
            hashpass = hashed_p.hexdigest()

            data = {'username': username, 'password': hashpass, 'salt': salt}
            if igdb_users.setd(hashusr, data):
                return 'OK'
            else: 
                return ' DB Error'
        else:
            return ' User Already Registered'

@app.route('/login', methods=['POST'])
def login_client():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password']

        hashed_username = hashlib.sha256()
        hashed_username.update(username.encode('utf-8'))
        hashusr = hashed_username.hexdigest()

        igdb_users = IGDB(os.path.join('dbs', 'users.json'))
        igdb_logclient = IGDB(os.path.join('dbs', 'logclient.json'))

        data:dict = igdb_users.getd(hashusr)

        if data is not None:
            #the user is registered
            salt = data.get('salt')
            hashed_p = hashlib.sha256()
            hashed_p.update(password.encode('utf-8'))
            hashed_p.update(salt.encode('utf-8'))
            h_pass = hashed_p.hexdigest() 
            if h_pass == data.get('password'):
                #check password for login
                luser:str = igdb_logclient.getd(hashusr)
                if luser is None:
                    #if user logs in for the first time
                    dt = datetime.now()
                    if igdb_logclient.setd(hashusr, dt.strftime(datetime.isoformat(dt))):
                        return 'OK'
                    else:
                        return ' DB Error'
                else:
                    #if user in already logged in
                    dt = datetime.now()
                    fmt = dt.isoformat()
                    if igdb_logclient.setd(hashusr, dt.strftime(datetime.isoformat(dt))):
                        return 'Already logged in'
                    else:
                        return ' DB Error'
            else:
                if igdb_logclient.deld(hashusr):
                    return ' Wrong Password! Your are logged out \n Please Try Again'
                else:
                    return ' Wrong Password! Please Try Again'
        else:
            #the user is not registered
            return ' User Not Registered'

@app.route('/logout', methods=['POST'])
def logout_client():
    if request.method == 'POST':
        username = request.json['username']

        hashed_username = hashlib.sha256()
        hashed_username.update(username.encode('utf-8'))
        hashusr = hashed_username.hexdigest()

        igdb_logclient = IGDB(os.path.join('dbs','logclient.json'))

        if igdb_logclient.getd(hashusr) is not None:
            if igdb_logclient.deld(hashusr):
                return 'OK'
            else:
                return ' DB Error while logging out'
        else:
            return ' User not logged in!'