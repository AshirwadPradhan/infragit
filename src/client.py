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
        '''    Register to the IntraGIT service. \n    Usage: register <username> <password>'''
        # parsed_inp = inp.split()
        if inp is not None:
            username = inp 
            password = getpass.getpass()
            res = requests.post('https://localhost:5683/register', json={'username':username, 'password':password }, verify='ca-public-key.pem')
            if 'OK' in res.text:
                print(f'Registration is Succesful for the username : {username}')
            else:
                print(f'ERROR : {res.text}')
        else:
            print('***Too Less Arguments: register')
    
    do_EOF = do_exit

IGCMD().cmdloop()