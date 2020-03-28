import requests
import json
from cmd import Cmd
import getpass
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512

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
        res = requests.get('https://localhost:5683/', verify='ca-public-key.pem')
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
            res = requests.post('https://localhost:5683/register', json={'username':username, 'password':password }, verify='ca-public-key.pem')
            if 'OK' in res.text:
                print(f'Registration is Succesful for the username : {username}')
            else:
                print(f'ERROR : {res.text}')
        elif len(inp) > 0 and len(parsed_prompt) > 1:
            print('*** Logout and then register')
        else:
            print('*** Too Less Arguments: register')
    
    def do_login(self, inp:str):
        '''    Login to the IntraGIT service. \n    Usage: login <username>'''
        parsed_prompt = IGCMD.prompt.split()
        if len(inp) > 0 and len(parsed_prompt) == 1:
            username = inp
            password = getpass.getpass()
            res = requests.post('https://localhost:5683/login', json={'username':username, 'password':password }, verify='ca-public-key.pem')
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
                res = requests.post('https://localhost:5683/logout', json={'username':inp}, verify='ca-public-key.pem')
                if 'OK' in res.text:
                    print(f'Successfully logged out!')
                    IGCMD.prompt = f'IGCMD> '
                else:
                    IGCMD.prompt = f'IGCMD> '
                    print(f'ERROR : {res.text}')
            elif len(inp) > 0:
                print(f'*** Logout command issued for wrong user {inp}')
                print(f'*** Current User {parsed_prompt[1]}')
        elif len(inp) > 0 and len(parsed_prompt) == 1:
            print(f'*** Invalid Command! No User Logged In')
        else:
            print(f'*** Too Less Arguments')

    def do_creater(self, inp:str):
        '''    Create a Repo. \n    Usage: create <repo name>'''
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
                res = requests.post('https://localhost:5683/create_repo', json={'repo_name':inp, 'cr':cr, 'admin':admin}, verify='ca-public-key.pem')
            except ConnectionError:
                print(' Connection Error: Please check validity of the repo...')
            json_data:dict = json.loads(res.text)
            # print(json_data)
            repo_name = json_data.get('repo_name', None)
            status = json_data.get('status', None)

            if status == 'OK' and repo_name is not None:
                print(f'Repo Created : {repo_name}')
            elif status != 'OK':
                print(f' ERROR: {status}')
            else:
                print(f'ERR: {res.text}')
        elif len(inp) > 0 and len(parsed_prompt) == 1:
            print('*** Login to create a repo')
        else:
            print('*** Too Less Arguments')
    


    # On EOF exit the command prompt
    do_EOF = do_exit

IGCMD().cmdloop()