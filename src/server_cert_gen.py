#Generate server's private key and generate csr

from pki_util import generate_private_key, generate_csr
import os

if __name__ == "__main__":
    certpath = os.path.join(os.getcwd(),'src','')
    private_key = generate_private_key(certpath+'server-private-key.pem', 'this')

    generate_csr(private_key=private_key,
                        filename=certpath+'server-csr.pem',
                        country='IN',
                        state='Rajasthan',
                        locality='Pilani',
                        org='InfraGIT',
                        alt_names=['localhost', '127.0.0.1'],
                        hostname='infragit.com')