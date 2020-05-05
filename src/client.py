import requests
import base64
import json
import os
from cmd import Cmd
import getpass
from zipfile import ZipFile
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from git import Repo

certpath = os.path.join(os.getcwd(),'src','')
# print(certpath)

class IGCMD(Cmd):

    prompt = 'IGCMD> '
    intro = 'This is IntraGIT client. Type ? to get list of commands'

    def do_exit(self, inp):
        '''exit the IntraGIT client'''
        parsed_prompt = IGCMD.prompt.split()
        if len(parsed_prompt) > 1:
            inp = parsed_prompt[1]
            l_inp = len(inp)
            inp = str(inp[:l_inp-1])
            print(f'Logging Out {inp}...')
            self.do_logout(inp)
        else:
            print('Exiting...')
        print('Bye')
        return True
    
    def do_test(self, inp):
        ''' Test is a test function '''
        res = requests.get('https://localhost:5683/', verify=certpath+'ca-public-key.pem')
        print(f'Testing {res.text}')
    
    def default(self, inp):
        if inp == 'quit' or inp == ':q':
            return self.do_exit(inp)
        else:
            print(f'*** Unknown Command : {inp}')
    
    def do_register(self, inp:str):
        '''    Register to the IntraGIT service. \n    Usage: register <username>'''
        parsed_prompt = IGCMD.prompt.split()
        if len(inp) > 0 and len(parsed_prompt) == 1:    
            parsed_inp = inp.split()
            username = parsed_inp[0]
            password = getpass.getpass()
            res = requests.post('https://localhost:5683/register', json={'username':username, 'password':password }, verify=certpath+'ca-public-key.pem')
            if 'OK' in res.text:
                print(f'Registration is Succesful for the username : {username}')
            else:
                print(f'ERROR : {res.text}')
        elif len(inp) > 0 and len(parsed_prompt) > 1:
            print('*** Logout and then register')
        else:
            print('*** Too Less Arguments: register')
    
    def do_adduser(self, inp:str):
        '''    Add an user to the list of auth users for a repo. \n    Usage: adduser <username>,<repo_name> \n
        This can only be used by the admin of the repo.
        '''
        parsed_prompt = IGCMD.prompt.split()
        if len(inp) > 0 and len(parsed_prompt) > 1:

            #admin
            admin = parsed_prompt[1]
            l_inp = len(admin)
            admin = str(admin[:l_inp-1])

            user, repo_name = inp.split(',')

            try:
                res = requests.post('https://localhost:5683/add_user', json={'repo_name':repo_name.strip(), 'user':user.strip(), 'admin':admin}, verify=certpath+'ca-public-key.pem')
            except ConnectionError:
                print(' Connection Error: Please check validity of the repo...')
            json_data:dict = json.loads(res.text)
            # print(json_data)
            user = json_data.get('user', None)
            status = json_data.get('status', None)

            if status == 'OK' and repo_name is not None:
                print(f'User Added : {user}')
            elif status != 'OK':
                print(f'{status}')
            else:
                print(f'{res.text}')

        elif len(inp) > 0 and len(parsed_prompt) == 1:
            print('*** Login to add a user')
        else:
            print('*** Too Less Arguments')

    def do_remuser(self, inp:str):
        '''    Add an user to the list of auth users for a repo. \n    Usage: adduser <username>,<repo_name> \n
        This can only be used by the admin of the repo.
        '''
        parsed_prompt = IGCMD.prompt.split()
        if len(inp) > 0 and len(parsed_prompt) > 1:

            #admin
            admin = parsed_prompt[1]
            l_inp = len(admin)
            admin = str(admin[:l_inp-1])

            user, repo_name = inp.split(',')

            #create client random
            cr_b = get_random_bytes(64)
            cr = SHA512.new(cr_b).hexdigest()

            try:
                res = requests.post('https://localhost:5683/rem_user', json={'repo_name':repo_name.strip(), 'user':user.strip(), 'admin':admin, 'cr':cr}, verify=certpath+'ca-public-key.pem')
            except ConnectionError:
                print(' Connection Error: Please check validity of the repo...')
            json_data:dict = json.loads(res.text)
            # print(json_data)
            user = json_data.get('user', None)
            status = json_data.get('status', None)

            if status == 'OK' and repo_name is not None:
                print(f'User Removed : {user}')
            elif status != 'OK':
                print(f'{status}')
            else:
                print(f'{res.text}')

        elif len(inp) > 0 and len(parsed_prompt) == 1:
            print('*** Login to add a user')
        else:
            print('*** Too Less Arguments')
        
    
    def do_login(self, inp:str):
        '''    Login to the IntraGIT service. \n    Usage: login <username>'''
        parsed_prompt = IGCMD.prompt.split()
        if len(inp) > 0 and len(parsed_prompt) == 1:
            username = inp
            password = getpass.getpass()
            res = requests.post('https://localhost:5683/login', json={'username':username, 'password':password }, verify=certpath+'ca-public-key.pem')
            if 'OK' in res.text:
                print(f'Successfully logged in as {username}')
                IGCMD.prompt = f'IGCMD {username}> '
            elif 'Already' in res.text:
                print(f'Already Logged in as {username}')
                IGCMD.prompt = f'IGCMD {username}> '
            else:
                IGCMD.prompt = f'IGCMD> '
                print(f'ERROR: {res.text}')
        elif len(inp) > 0 and len(parsed_prompt) > 1:
            print(f'*** Already logged in as {parsed_prompt[1]}! Log Out First!')
        else:
            print('*** Too Less Arguments: login')
    
    def do_logout(self, inp:str):
        '''    Logout to the IntraGIT service. \n    Usage: logout <username>'''
        parsed_prompt = IGCMD.prompt.split()
        if len(inp) > 0 and len(parsed_prompt) > 1:
            if inp+'>' == parsed_prompt[1]:
                try:
                    res = requests.post('https://localhost:5683/logout', json={'username':inp}, verify=certpath+'ca-public-key.pem')
                    if 'OK' in res.text:
                        print(f'Successfully logged out!')
                        IGCMD.prompt = f'IGCMD> '
                    else:
                        IGCMD.prompt = f'IGCMD> '
                        print(f'ERROR : {res.text}')
                except Exception:
                    IGCMD.prompt = f'IGCMD> '
                    print(f'***ERROR : Not a Graceful logout')
            elif len(inp) > 0:
                print(f'*** Logout command issued for wrong user {inp}')
                print(f'*** Current User {parsed_prompt[1]}')
        elif len(inp) > 0 and len(parsed_prompt) == 1:
            print(f'*** Invalid Command! No User Logged In')
        else:
            print(f'*** Too Less Arguments')

    def do_creater(self, inp:str):
        '''    Create a Repo. \n    Usage: creater <repo name>'''
        parsed_prompt = IGCMD.prompt.split()
        if len(inp) > 0 and len(parsed_prompt) > 1:

            #admin
            admin = parsed_prompt[1]
            l_inp = len(admin)
            admin = str(admin[:l_inp-1])

            #create client random
            cr_b = get_random_bytes(64)
            cr = SHA512.new(cr_b).hexdigest()
            try:
                res = requests.post('https://localhost:5683/create_repo', json={'repo_name':inp, 'cr':cr, 'admin':admin}, verify=certpath+'ca-public-key.pem')
            except ConnectionError:
                print(' Connection Error: Please check validity of the repo...')
            json_data:dict = json.loads(res.text)
            # print(json_data)
            repo_name = json_data.get('repo_name', None)
            status = json_data.get('status', None)

            if status == 'OK' and repo_name is not None:
                print(f'Repo Created : {repo_name}')
                
                #create a local repo
                c_path = os.path.join('src','dbctest', repo_name)
                os.mkdir(c_path)
                c_repo = Repo.init(c_path)

                with open(c_path + "/README.md", 'x') as readme: readme.write('#' + repo_name) 
                c_repo.index.add("README.md")
                c_repo.index.commit("Initial commit")
                
                self.do_pushr(repo_name)

            elif status != 'OK':
                print(f'{status}')
            else:
                print(f'{res.text}')
        elif len(inp) > 0 and len(parsed_prompt) == 1:
            print('*** Login to create a repo')
        else:
            print('*** Too Less Arguments')
    
    def do_pushr(self, inp:str):
        '''    Push a Repo with local changes \n    Usage: pushr <repo name>'''
        parsed_prompt = IGCMD.prompt.split()
        if len(inp) > 0 and len(parsed_prompt) > 1:

            #user
            user = parsed_prompt[1]
            l_inp = len(user)
            user = str(user[:l_inp-1])

            #data
            c_path = os.path.join('src','dbctest', inp)
            c_repo = Repo(c_path)
            
            try:
                #get the session key for encryption
                res = requests.post('https://localhost:5683/get_sk', json={'repo_name':inp, 'user':user}, verify=certpath+'ca-public-key.pem')
                sess_data = json.loads(res.text)
                session_key = sess_data.get('session_key', None)
                # print(session_key)
                if (session_key != ''):
                    #get unencrypted compressed data
                    with open(c_path + '.zip', 'wb+') as archive_file: 
                        c_repo.archive(archive_file, format='zip')
                    with open(c_path + '.zip', 'rb') as archive_file:
                        data = archive_file.read()
                    os.remove(c_path + '.zip')

                    #encrypt the data 
                    key = session_key[:32].encode('utf-8')
                    
                    b64_data = base64.b64encode(data)
                    cipher = AES.new(key, AES.MODE_GCM)
                    ciphertext, tag = cipher.encrypt_and_digest(b64_data)
                    enc_data = bytearray(cipher.nonce)
                    enc_data.extend(tag)
                    enc_data.extend(ciphertext)
                    enc_data = enc_data.hex()

                    try:
                        res = requests.post('https://localhost:5683/push_repo', json={'repo_name':inp, 'data':enc_data, 'user':user}, verify=certpath+'ca-public-key.pem')
                    except ConnectionError:
                        print(' Connection Error: Please check validity of the repo...')
                    json_data:dict = json.loads(res.text)
                    # print(json_data)
                    repo_name = json_data.get('repo_name', None)
                    status = json_data.get('status', None)

                    if status == 'OK' and repo_name is not None:
                        print(f'Successfully pushed changes to Repo : {repo_name}')
                    elif status != 'OK':
                        print(f'{status}')
                    else:
                        print(f'{res.text}')
                else:
                    print('Unauthorized Access!: Not Allowed')
            except FileNotFoundError:
                print(f'*** The repo {inp} is not present locally')
        elif len(inp) > 0 and len(parsed_prompt) == 1:
            print('*** Login to push to a repo')
        else:
            print('*** Too Less Arguments')


    def do_pullr(self, inp:str):
        '''    Pull a Repo with local changes \n    Usage: pullr <repo name>'''
        parsed_prompt = IGCMD.prompt.split()
        if len(inp) > 0 and len(parsed_prompt) > 1:

            #user
            user = parsed_prompt[1]
            l_inp = len(user)
            user = str(user[:l_inp-1])
            
            #pull from remote repo
            try:
                res = requests.post('https://localhost:5683/pull_repo', json={'repo_name':inp, 'user':user}, verify=certpath+'ca-public-key.pem')
                #data
                json_data:dict = json.loads(res.text)
                data = json_data.get('data', None)
                status = json_data.get('status', None)
                repo_name = json_data.get('repo_name', None)

                if status == 'OK' and data is not None:

                    #decrypt the data
                    #format the data
                    enc_data = bytes.fromhex(data)
                    nonce = enc_data[:16]
                    tag = enc_data[16:32]
                    ciphertext = enc_data[32:]
                    #get the session key for decryption
                    ress = requests.post('https://localhost:5683/get_sk', json={'repo_name':inp, 'user':user}, verify=certpath+'ca-public-key.pem')
                    sess_data = json.loads(ress.text)
                    session_key = sess_data.get('session_key', None)

                    if session_key != '':
                        key = session_key[:32].encode('utf-8')
                    
                        cipher = AES.new(key, AES.MODE_GCM, nonce)
                        try:
                            b64_data = cipher.decrypt_and_verify(ciphertext, tag)
                            #edit the repo
                            plain_data = base64.b64decode(b64_data)
                            c_path = os.path.join('src','dbctest', inp)
                            try:
                                with open(c_path + '.zip', 'wb+') as f:
                                    f.write(plain_data)
                                with ZipFile(c_path + '.zip') as zipObj:
                                    zipObj.extractall(c_path)
                                os.remove(c_path + '.zip')
                                print(f'Successfully pulled changes from Repo : {repo_name}')
                            except:
                                print('*** Error writing to local repo.. Pull again from remote')
                        except ValueError:
                            print('*** Tampered Data')
                    else:
                        print('*** Unauthorized Access!: Not Allowed')
                elif status == 'OK' and data is None:
                    print('*** No data received')
                elif status != 'OK':
                    print(f' {status}')
                else:
                    print(f'{res.text}')
            except ConnectionError:
                print(' Connection Error: Please check validity of the repo...')

        elif len(inp) > 0 and len(parsed_prompt) == 1:
            print('*** Login to push to a repo')
        else:
            print('*** Too Less Arguments')


    # On EOF exit the command prompt
    do_EOF = do_exit

IGCMD().cmdloop()