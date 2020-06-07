#Generate server's private key and generate csr

from pki_util import generate_private_key, generate_csr
import os

if __name__ == "__main__":
    certpath = os.path.join(os.getcwd(),'src','')
    private_key = generate_private_key(certpath+'repo-private-key.pem', 'this')

    generate_csr(private_key=private_key,
                        filename=certpath+'repo-csr.pem',
                        country='US',
                        state='New York',
                        locality='Manhattan',
                        org='AWS',
                        alt_names=['localhost', '127.0.0.1'],
                        hostname='s3.aws.com')