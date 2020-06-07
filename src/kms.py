from Crypto.Protocol.KDF import PBKDF2, bcrypt, scrypt
from Crypto.Hash import SHA512, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange
import base64


def get_root_key(client_random, server_random) -> str:
    
    dklen = 64
    count = 1000000

    #derive keys from PBKDF2 using client_random as password and server_random as salt
    keys = PBKDF2(client_random,
                    server_random,
                    dkLen=dklen,
                    count=count,
                    hmac_hash_module=SHA512)
    
    #get two 32 byte key from keys and encode the with b64 
    part_f = keys[:32]
    f_b64 = base64.b64encode(part_f)
    # f_str = f_b64.decode('utf-8')

    part_l = keys[32:]
    l_b64 = base64.b64encode(part_l)
    # l_str = l_b64.decode('utf-8')

    try:
        b64_bcf = base64.b64encode(SHA256.new(f_b64).digest())
        b64_bcl = base64.b64encode(SHA256.new(l_b64).digest())
        
        #use of HSM module to get cryptographically secure PRN
        cost_f = randrange(13, 14)
        cost_l = randrange(13, 14)

        #now bcrypt the keys that we got before
        print(len(b64_bcf))
        bcrypt_hash_f = bcrypt(b64_bcf, cost_f)
        bcrypt_hash_l = bcrypt(b64_bcl, cost_f)

        sk_obj = SHA512.new(bcrypt_hash_f)
        sk_obj.update(bcrypt_hash_l)

        return sk_obj.hexdigest()


    except ValueError:
        print('Too much bytes to bcrypt!!')


def get_data_key(shared_secret, server_random) -> str:

    d_key_length = 64
    #based on Colin Percival suggested choice of Parameters for scrypt in 2009
    # since data key will be used for repo(file) encryption we use N = 2^20
    # print('Scripting...')
    data_key = scrypt(shared_secret, server_random, key_len=d_key_length, N=2**20, r=8, p=1)
    # print('Done Scripting....')
    dk_obj = SHA256.new(data_key)

    return dk_obj.hexdigest()



# if __name__ == "__main__":
#     # print(get_root_key('this is random', 'this also very random'))
#     print(get_data_key(get_root_key('this is random', 'this also very random'), 'this is also very random'))
    # d = get_data_key('459e353e92cb3fb5a505f12165336b3e83a17c8c3658e80a8400382372aeed7566ef397b80a0d3434c59a2675953ee94db3a0eaac35fc69f0b403b397dbc8e4d','this is random')
    # print(d)
