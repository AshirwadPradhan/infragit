# The GATEWAY for the client (entry point to the application)
from flask import Flask, request
from localdb import IGDB
import hashlib
import os

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

        hashed_username = hashlib.sha256()
        hashed_username.update(username.encode('utf-8'))
        hashusr = hashed_username.hexdigest()

        igdb = IGDB(os.path.join('dbs','users.json'))

        if not igdb.getd(hashusr):
            data = {'username': username, 'password': password}
            if igdb.setd(hashusr, data):
                return 'OK'
            else: 
                return ' DB Error'
        else:
            return ' User Already Registered'