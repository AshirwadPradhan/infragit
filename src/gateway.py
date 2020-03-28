# The GATEWAY for the client (entry point to the application)
from flask import Flask, request, jsonify
from localdb import IGDB
import hashlib
import os
from datetime import datetime
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
import base64
from kms import get_session_key, get_data_key
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

SECRET_MESSAGE = 'very secret'
app = Flask(__name__)

def encrypt_with_dk(data, root_key, server_random):
    ''' Perform envelope encryption '''

    #get the data key
    data_key = get_data_key(root_key, server_random)
    data_key = data_key[:32]
    data_key = bytes(data_key, encoding='utf-8')
    # print(len(data_key)) 32

    #encrypt data with data key  c = ENCR(data_key, data)
    # print('this before AES 1')
    cipher = AES.new(data_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    ct_iv = cipher.iv
    # print(len(ct_iv))  16

    # print('this before AES 2')
    #encrypt data key with root key   encKey = ENCR(root_key, data_key)
    cp = AES.new(root_key, AES.MODE_CBC)
    encKey = cp.encrypt(pad(data_key, AES.block_size))
    k_iv = cp.iv
    # print(len(k_iv))  16
    # print(len(encKey))  48

    enc_msg = bytearray(ct_iv)
    enc_msg.extend(k_iv)
    enc_msg.extend(encKey)
    enc_msg.extend(ciphertext)
    enc_msg = enc_msg.hex()

    return enc_msg

def decrypt_with_dk(data, root_key, server_random):
    ''' Perform envelope decryption'''

    #get the binary data in required format
    #extract all the info back as maintained in the structure
    data = bytes.fromhex(data)
    ct_iv = data[:16]
    k_iv = data[16:32]
    encKey = data[32:80]
    ciphertext = data[80:]

    # decipher the data key
    cp = AES.new(root_key, AES.MODE_CBC, k_iv)
    data_key = unpad(cp.decrypt(encKey), AES.block_size)

    # decipher the ciphertext using the data key
    cipher = AES.new(data_key, AES.MODE_CBC, ct_iv)
    plain_text = unpad(cipher.decrypt(ciphertext), AES.block_size)

    # print(plain_text.decode('utf-8'))
    return plain_text.decode('utf-8')

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

        #calculate the hash of the username
        hashed_username = hashlib.sha256()
        hashed_username.update(username.encode('utf-8'))
        hashusr = hashed_username.hexdigest()

        igdb_logclient = IGDB(os.path.join('dbs','logclient.json'))

        #Check if the user is logged in 
        if igdb_logclient.getd(hashusr) is not None:
            #if the user is deleted from logclient database return OK 
            if igdb_logclient.deld(hashusr):
                return 'OK'
            else:
                return ' DB Error while logging out'
        else:
            return ' User not logged in!'

@app.route('/create_repo', methods=['POST'])
def create_repo():
    if request.method == 'POST':
        repo_name = request.json['repo_name']

        #store the session key with admin of the repo
        igdb_repoinf = IGDB(os.path.join('dbs', 'repoinf.json'))

        if igdb_repoinf.getd(repo_name) is None:
            client_random = request.json['cr']
            admin = request.json['admin']
            #create server random 
            sr_b = get_random_bytes(64)
            server_random = SHA512.new(sr_b).hexdigest()

            #get the session key of the repo
            session_key = get_session_key(client_random, server_random)
            print(session_key)
            
            #create the repo
            c_path = os.path.join('dbtest', repo_name)
            with open(c_path, 'w+') as f:
                f.write('This is a dummy repo')

            data = {'admin': admin, 'session_key': session_key, 'server_random': server_random, 'users': [admin]}
            if igdb_repoinf.setd(repo_name, data):
                d = {'repo_name': repo_name, 'status': 'OK'}
            else:
                d = {'status': f'ERROR: Error in creating {repo_name} in the repository'}
        else:
            d = {'status': f'ERROR: {repo_name} already present'}
        
        return jsonify(d)

@app.route('/push_repo', methods=['POST'])
def push_repo():
    if request.method == 'POST':
        repo_name = request.json['repo_name']
        user = request.json['user']

        # push the data to the repo
        igdb_repoinf = IGDB(os.path.join('dbs', 'repoinf.json'))

        if igdb_repoinf.getd(repo_name) is not None:

            repo_info = igdb_repoinf.getd(repo_name)
            repo_users = repo_info['users']
            if user in repo_users:
                data = request.json['data']
                
                #format the data
                enc_data = bytes.fromhex(data)
                nonce = enc_data[:16]
                tag = enc_data[16:32]
                ciphertext = enc_data[32:]
                
                #get session key
                session_key = repo_info['session_key']

                if session_key is not None:
                    key = session_key[:32].encode('utf-8')
                    cipher = AES.new(key, AES.MODE_GCM, nonce)
                    try:
                        plain_data = cipher.decrypt_and_verify(ciphertext, tag)
                        
                        #get server random
                        server_random = repo_info['server_random']
                        # envelope encryption
                        # print('start ee encr')
                        ee_plain_data = encrypt_with_dk(plain_data, key, server_random)
                        #edit the repo
                        # ee_plain_data = ee_plain_data.decode('utf-8')
                        c_path = os.path.join('dbtest', repo_name)
                        with open(c_path, 'w+') as f:
                            f.write(ee_plain_data)
                        
                        d = {'repo_name': repo_name, 'status': 'OK'}
                    except ValueError:
                        d = {'status': 'Tampered Data'}
                else:
                    d = {'status': 'Unable to get session key.. Please check validity of the repo'}
            else:
                d = {'status': f'ERROR: Authentication Error! User not in list of valid users for this repo'}
        else:
            d = {'status': f'ERROR: Invalid {repo_name} repo'}
        
        return jsonify(d)

@app.route('/pull_repo', methods=['POST'])
def pull_repo():
    if request.method == 'POST':
        repo_name = request.json['repo_name']
        user = request.json['user']

        # pull the data to the repo
        igdb_repoinf = IGDB(os.path.join('dbs', 'repoinf.json'))

        if igdb_repoinf.getd(repo_name) is not None:

            repo_info = igdb_repoinf.getd(repo_name)
            repo_users = repo_info['users']
            if user in repo_users:
                
                #read the repo
                c_path = os.path.join('dbtest', repo_name)
                with open(c_path, 'r') as f:
                    data = f.read()
                
                #get session key
                session_key = repo_info['session_key']
                #get server random
                server_random = repo_info['server_random']

                if session_key is not None:
                    key = session_key[:32].encode('utf-8')

                    # envelope decryption
                    data = decrypt_with_dk(data, key, server_random)
                    
                    #start the encryption process
                    cipher = AES.new(key, AES.MODE_GCM)
                    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))

                    enc_data = bytearray(cipher.nonce)
                    enc_data.extend(tag)
                    enc_data.extend(ciphertext)
                    enc_data = enc_data.hex()
                        
                    d = {'repo_name': repo_name, 'data': enc_data, 'status': 'OK'}
                else:
                    d = {'status': 'Unable to get session key.. Please check validity of the repo'}
            else:
                d = {'status': f'ERROR: Authentication Error! User not in list of valid users for this repo'}
        else:
            d = {'status': f'ERROR: Invalid {repo_name} repo'}
        
        return jsonify(d)

@app.route('/get_sk', methods=['POST'])
def get_sk():
    if request.method == 'POST':
        repo_name = request.json['repo_name']
        user = request.json['user']

        igdb_repoinf = IGDB(os.path.join('dbs', 'repoinf.json'))

        if igdb_repoinf.getd(repo_name) is not None:

            repo_info = igdb_repoinf.getd(repo_name)
            repo_users = repo_info['users']
            if user in repo_users:
                #get the session key
                session_key = repo_info['session_key']
                d = {'session_key': session_key}

                return jsonify(d)

        return None
            