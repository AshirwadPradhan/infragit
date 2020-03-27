import requests
from cmd import Cmd
import getpass

# def get_secret_message():
#     url = 'https://localhost:5683'
#     response = requests.get(url, verify='ca-public-key.pem')
#     print(f'The secret message is : {response.text}')

# if __name__ == "__main__":
#     get_secret_message()

class IGCMD(Cmd):

    prompt = 'IGCMD> '
    intro = 'This is IntraGIT client. Type ? to get list of commands'

    def do_exit(self, inp):
        '''exit the IntraGIT client'''
        print('Bye')
        return True
    
    def do_add(self, inp):
        ''' Add is dummy function '''
        print(f'Adding {inp}')
    
    def default(self, inp):
        if inp == 'quit' or inp == ':q':
            return self.do_exit(inp)
        else:
            print(f'***Unknown Command : {inp}')
    
    def do_register(self, inp:str):
        '''    Register to the IntraGIT service. \n    Usage: register <username>'''
        if inp is not None:    
            parsed_inp = inp.split()
            username = parsed_inp[0]
            password = getpass.getpass()
            res = requests.post('https://localhost:5683/register', json={'username':username, 'password':password }, verify='ca-public-key.pem')
            if 'OK' in res.text:
                print(f'Registration is Succesful for the username : {username}')
            else:
                print(f'ERROR : {res.text}')
        else:
            print('***Too Less Arguments: register')
    
    def do_login(self, inp:str):
        '''    Login to the IntraGIT service. \n    Usage: login <username>'''
        parsed_prompt = IGCMD.prompt.split()
        if inp is not None and len(parsed_prompt) == 1:
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
        elif len(parsed_prompt) > 1:
            print(f'***Already logged in as {parsed_prompt[1]}! Log Out First!')
        else:
            print('***Too Less Arguments: login')
    
    def do_logout(self, inp:str):
        '''    Logout to the IntraGIT service. \n    Usage: logout <username>'''
        parsed_prompt = IGCMD.prompt.split()
        if inp is not None and len(parsed_prompt) > 1:
            if inp+'>' == parsed_prompt[1]:
                res = requests.post('https://localhost:5683/logout', json={'username':inp}, verify='ca-public-key.pem')
                if 'OK' in res.text:
                    print(f'Successfully logged out!')
                    IGCMD.prompt = f'IGCMD> '
                else:
                    IGCMD.prompt = f'IGCMD> '
                    print(f'ERROR : {res.text}')
            else:
                print(f'***Logout command issued for wrong user {inp}')
                print(f'***Current User {parsed_prompt[1]}')
        elif len(parsed_prompt) == 1:
            print(f'***Invalid Command! No User Logged In')
        else:
            print(f'***Too Less Arguments')
    do_EOF = do_exit

IGCMD().cmdloop()